from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable

_RE_COPPIA = re.compile(r"([a-z_0-9]+):([^\s,)]+)", re.I)
_RE_BBR = re.compile(r"bbr:\(([^)]*)\)")
_UNITA = {"k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12}


def _numero(grezzo: str) -> float | None:
    if not grezzo:
        return None
    grezzo = grezzo.split("/")[0]
    m = re.match(r"^([0-9]*\.?[0-9]+)\s*([kmgt])?(bps|ms|b)?$", grezzo.strip(), re.I)
    if not m:
        try:
            return float(grezzo)
        except ValueError:
            return None
    valore = float(m.group(1))
    if m.group(2):
        valore *= _UNITA[m.group(2).lower()]
    return valore


@dataclass
class Socket:
    stato: str = ""
    locale: str = ""
    remoto: str = ""
    congestione: str | None = None
    rtt_ms: float | None = None
    minrtt_ms: float | None = None
    cwnd: float | None = None
    ritrasmessi: float | None = None
    byte_inviati: float | None = None
    byte_ricevuti: float | None = None
    segs_out: float | None = None
    segs_in: float | None = None
    pacing_rate: float | None = None
    delivery_rate: float | None = None
    bbr_bw: float | None = None
    bbr_mrtt: float | None = None
    bbr_pacing_gain: float | None = None
    bbr_cwnd_gain: float | None = None
    app_limited: bool | None = None
    busy_ms: float | None = None
    rwnd_limited_ms: float | None = None
    sndbuf_limited_ms: float | None = None
    ritrasmessi_totali: float | None = None

    @property
    def peer_ip(self) -> str:
        return self.remoto.rsplit(":", 1)[0] if ":" in self.remoto else self.remoto

    def come_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None and v != ""}


_STATI = {"ESTAB", "SYN-SENT", "SYN-RECV", "FIN-WAIT-1", "FIN-WAIT-2", "TIME-WAIT",
          "CLOSE-WAIT", "LAST-ACK", "LISTEN", "CLOSING", "UNCONN", "CLOSED"}


def analizza_ss(testo: str) -> list[Socket]:
    socket_trovati: list[Socket] = []
    corrente: Socket | None = None
    for riga in testo.splitlines():
        if not riga.strip():
            continue
        rientrata = riga[:1].isspace()
        campi = riga.split()
        if not rientrata:
            if campi[0] == "State" or campi[0].startswith("Recv-Q"):
                continue
            if campi[0].upper() not in _STATI and len(campi) < 4:
                continue
            corrente = Socket(stato=campi[0])
            if len(campi) >= 5:
                corrente.locale, corrente.remoto = campi[3], campi[4]
            socket_trovati.append(corrente)
            resto = " ".join(campi[5:])
            if resto:
                _dettagli(corrente, resto)
        elif corrente is not None:
            _dettagli(corrente, riga.strip())
    return socket_trovati


class CampoBBR(StrEnum):
    BW = "bw"
    MRTT = "mrtt"
    PACING_GAIN = "pacing_gain"
    CWND_GAIN = "cwnd_gain"


def _dettagli(s: Socket, testo: str) -> None:
    primo = testo.split(maxsplit=1)[0] if testo.split() else ""
    if primo and ":" not in primo and "(" not in primo and s.congestione is None:
        s.congestione = primo
    m = _RE_BBR.search(testo)
    if m:
        for chiave, valore in _RE_COPPIA.findall(m.group(1)):
            k = chiave.lower()
            match k:
                case CampoBBR.BW:
                    s.bbr_bw = _numero(valore)
                case CampoBBR.MRTT:
                    s.bbr_mrtt = _numero(valore)
                case CampoBBR.PACING_GAIN:
                    s.bbr_pacing_gain = _numero(valore)
                case CampoBBR.CWND_GAIN:
                    s.bbr_cwnd_gain = _numero(valore)
        testo = testo[:m.start()] + " " + testo[m.end():]
    mappa = {
        "rtt": "rtt_ms", "minrtt": "minrtt_ms", "cwnd": "cwnd",
        "retrans": "ritrasmessi", "bytes_sent": "byte_inviati",
        "bytes_received": "byte_ricevuti", "segs_out": "segs_out", "segs_in": "segs_in",
    }
    for chiave, valore in _RE_COPPIA.findall(testo):
        campo = mappa.get(chiave.lower())
        if campo:
            n = _numero(valore)
            if n is not None:
                setattr(s, campo, n)
    if re.search(r"\brtt:", testo):
        s.app_limited = bool(re.search(r"\bapp_limited\b", testo))
    for nome, campo in (("busy", "busy_ms"), ("rwnd_limited", "rwnd_limited_ms"),
                        ("sndbuf_limited", "sndbuf_limited_ms")):
        m3 = re.search(rf"\b{nome}:([0-9.]+)ms", testo)
        if m3:
            setattr(s, campo, float(m3.group(1)))
    m4 = re.search(r"\bretrans:[0-9]+/([0-9]+)", testo)
    if m4:
        s.ritrasmessi_totali = float(m4.group(1))
    for nome, campo in (("pacing_rate", "pacing_rate"), ("delivery_rate", "delivery_rate")):
        m2 = re.search(rf"{nome}\s+([0-9.]+[kKmMgG]?bps)", testo)
        if m2:
            setattr(s, campo, _numero(m2.group(1)))


def leggi_ss(comando: list[str] | None = None) -> list[Socket]:
    cmd = comando or ["ss", "-tin"]
    if shutil.which(cmd[0]) is None:
        return []
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return []
    return analizza_ss(out.stdout)


def analizza_snmp(testo: str) -> dict[str, float]:
    valori: dict[str, float] = {}
    righe = testo.splitlines()
    for i in range(0, len(righe) - 1, 2):
        intestazione, dati = righe[i].split(), righe[i + 1].split()
        if not intestazione or not dati or intestazione[0] != dati[0]:
            continue
        prefisso = intestazione[0].rstrip(":")
        for nome, grezzo in zip(intestazione[1:], dati[1:]):
            try:
                valori[f"{prefisso}.{nome}"] = float(grezzo)
            except ValueError:
                continue
    return valori


def leggi_contatori_rete() -> dict[str, float]:
    valori: dict[str, float] = {}
    for percorso in ("/proc/net/snmp", "/proc/net/netstat"):
        try:
            with open(percorso, encoding="utf-8") as f:
                valori.update(analizza_snmp(f.read()))
        except OSError:
            continue
    return valori


@dataclass
class StatoBordo:
    cpu_pct: float | None = None
    memoria_usata_mb: float | None = None
    disco_libero_mb: float | None = None
    processi: int | None = None
    carico_1min: float | None = None
    extra: dict[str, float] = field(default_factory=dict)

    def come_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items()
             if k != "extra" and v is not None}
        d.update(self.extra)
        return d


CGROUP_PREDEFINITO = "/sys/fs/cgroup"


class LettoreBordo:
    def __init__(self, radice_disco: str = "/", cgroup: str | None = CGROUP_PREDEFINITO,
                 archivio: str | None = None, capacita_archivio_mb: float | None = None,
                 orologio: Callable[[], float] = time.monotonic) -> None:
        self._radice = radice_disco
        self._cpu_prec: tuple[float, float] | None = None
        self._cgroup = Path(cgroup) if cgroup else None
        self._archivio = Path(archivio) if archivio else None
        self._capacita_mb = capacita_archivio_mb
        self._orologio = orologio
        self._cpu_cg_prec: tuple[float, float] | None = None
        self.fonte_cpu = self.fonte_memoria = self.fonte_disco = "ospite"

    def leggi(self) -> StatoBordo:
        s = StatoBordo()
        s.cpu_pct = self._cpu()
        s.memoria_usata_mb = self._memoria()
        s.disco_libero_mb = self._disco()
        s.processi = self._processi()
        s.carico_1min = self._carico()
        return s

    def _leggi_cgroup(self, nome: str) -> str | None:
        if self._cgroup is None:
            return None
        try:
            return (self._cgroup / nome).read_text(encoding="utf-8")
        except OSError:
            return None

    def _quota_cpu(self) -> float:
        testo = self._leggi_cgroup("cpu.max")
        if testo:
            parti = testo.split()
            if len(parti) == 2 and parti[0] != "max":
                try:
                    q, periodo = float(parti[0]), float(parti[1])
                    if q > 0 and periodo > 0:
                        return q / periodo
                except ValueError:
                    pass
        return float(os.cpu_count() or 1)

    def _cpu_cgroup(self) -> tuple[bool, float | None]:
        testo = self._leggi_cgroup("cpu.stat")
        if not testo:
            return False, None
        uso = None
        for riga in testo.splitlines():
            parti = riga.split()
            if len(parti) == 2 and parti[0] == "usage_usec":
                try:
                    uso = float(parti[1])
                except ValueError:
                    return False, None
        if uso is None:
            return False, None
        adesso = self._orologio()
        prec = self._cpu_cg_prec
        self._cpu_cg_prec = (uso, adesso)
        if prec is None or adesso <= prec[1]:
            return True, None
        secondi_cpu = (uso - prec[0]) / 1e6
        quota = self._quota_cpu()
        return True, max(0.0, min(100.0, 100.0 * secondi_cpu / (adesso - prec[1]) / quota))

    def _cpu(self) -> float | None:
        letto, valore = self._cpu_cgroup()
        if letto:
            self.fonte_cpu = "cgroup"
            return valore
        self.fonte_cpu = "ospite"
        try:
            with open("/proc/stat", encoding="utf-8") as f:
                campi = f.readline().split()
            if campi[0] != "cpu":
                return None
            numeri = [float(x) for x in campi[1:]]
            totale, inattivo = sum(numeri), numeri[3]
        except (OSError, IndexError, ValueError):
            return None
        prec = self._cpu_prec
        self._cpu_prec = (totale, inattivo)
        if prec is None:
            return None
        d_tot, d_idle = totale - prec[0], inattivo - prec[1]
        if d_tot <= 0:
            return None
        return max(0.0, min(100.0, 100.0 * (1.0 - d_idle / d_tot)))

    def _memoria(self) -> float | None:
        testo = self._leggi_cgroup("memory.stat")
        if testo:
            for riga in testo.splitlines():
                parti = riga.split()
                if len(parti) == 2 and parti[0] == "anon":
                    try:
                        self.fonte_memoria = "cgroup"
                        return float(parti[1]) / (1024.0 * 1024.0)
                    except ValueError:
                        break
        self.fonte_memoria = "ospite"
        try:
            info: dict[str, float] = {}
            with open("/proc/meminfo", encoding="utf-8") as f:
                for riga in f:
                    parti = riga.split()
                    if len(parti) >= 2:
                        info[parti[0].rstrip(":")] = float(parti[1])
            totale = info.get("MemTotal")
            disponibile = info.get("MemAvailable")
            if totale is None or disponibile is None:
                return None
            return (totale - disponibile) / 1024.0
        except (OSError, ValueError):
            return None

    def _disco(self) -> float | None:
        if self._archivio is not None and self._capacita_mb is not None:
            usato = 0
            for cartella, _sotto, file in os.walk(self._archivio):
                for nome in file:
                    try:
                        usato += os.path.getsize(os.path.join(cartella, nome))
                    except OSError:
                        continue
            self.fonte_disco = "archivio"
            return max(0.0, self._capacita_mb - usato / (1024.0 * 1024.0))
        self.fonte_disco = "ospite"
        try:
            st = os.statvfs(self._radice)
            return st.f_bavail * st.f_frsize / (1024.0 * 1024.0)
        except (OSError, AttributeError):
            return None

    @staticmethod
    def _processi() -> int | None:
        try:
            return sum(1 for n in os.listdir("/proc") if n.isdigit())
        except OSError:
            return None

    @staticmethod
    def _carico() -> float | None:
        try:
            return os.getloadavg()[0]
        except (OSError, AttributeError):
            return None


def leggi_costo_proprio() -> dict[str, float]:
    risultato: dict[str, float] = {}
    try:
        with open(f"/proc/{os.getpid()}/statm", encoding="utf-8") as f:
            pagine = f.read().split()
        risultato["ids_rss_mb"] = float(pagine[1]) * os.sysconf("SC_PAGE_SIZE") / 1048576.0
    except (OSError, IndexError, ValueError, AttributeError):
        pass
    try:
        risultato["ids_cpu_s"] = time.process_time()
    except Exception:
        pass
    return risultato
