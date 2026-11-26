from __future__ import annotations

import json
import math
import os
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ids.features import FeatureVector

ALFA = 0.05
MIN_CAMPIONI = 20
EPS = 1e-9

MASSIMI_VALORI_DISTINTI = 32


@dataclass
class Statistica:
    n: int = 0
    media: float = 0.0
    varianza: float = 0.0
    minimo: float = math.inf
    massimo: float = -math.inf
    campioni: list[float] = field(default_factory=list)
    _limite_campioni: int = 400
    _passo_campioni: int = 1
    _visti_campioni: int = 0
    _alto_salvato: float | None = None
    _mediana_salvata: float | None = None
    _mad_salvata: float | None = None
    conteggi: dict[float, int] = field(default_factory=dict)
    _conteggi_validi: bool = True

    def aggiorna(self, x: float) -> None:
        self.n += 1
        if self.n == 1:
            self.media = x
            self.varianza = 0.0
        else:
            delta = x - self.media
            self.media += ALFA * delta
            self.varianza = (1 - ALFA) * (self.varianza + ALFA * delta * delta)
        self.minimo = min(self.minimo, x)
        self.massimo = max(self.massimo, x)
        if self._conteggi_validi:
            if not float(x).is_integer() or (
                    x not in self.conteggi
                    and len(self.conteggi) >= MASSIMI_VALORI_DISTINTI):
                self._conteggi_validi = False
                self.conteggi = {}
            else:
                self.conteggi[float(x)] = self.conteggi.get(float(x), 0) + 1
        self._visti_campioni += 1
        if (self._visti_campioni - 1) % self._passo_campioni == 0:
            self.campioni.append(x)
            if len(self.campioni) >= self._limite_campioni:
                self.campioni = self.campioni[::2]
                self._passo_campioni *= 2

    @property
    def sigma(self) -> float:
        return math.sqrt(max(self.varianza, 0.0))

    @property
    def differenza_estremi(self) -> float:
        if self.minimo == math.inf or self.massimo == -math.inf:
            return 0.0
        return max(0.0, (self.massimo - self.minimo) / 6.0)

    @property
    def pavimento(self) -> float:
        return max(self.sigma, self.differenza_estremi, abs(self.media) * 0.02, EPS)

    @property
    def percentile_alto(self) -> float:
        if self._alto_salvato is not None:
            return self._alto_salvato
        if self._conteggi_validi and self.conteggi:
            n = sum(self.conteggi.values())
            if n >= 50:
                posizione = min(n - 1, int(n * 0.99))
                cumulato = 0
                for valore in sorted(self.conteggi):
                    cumulato += self.conteggi[valore]
                    if cumulato > posizione:
                        return valore
        if len(self.campioni) >= 50:
            ordinati = sorted(self.campioni)
            return ordinati[min(len(ordinati) - 1, int(len(ordinati) * 0.99))]
        return self.massimo if self.massimo != -math.inf else self.media

    @property
    def mediana(self) -> float:
        if self._mediana_salvata is not None:
            return self._mediana_salvata
        return statistics.median(self.campioni) if self.campioni else self.media

    @property
    def mad(self) -> float:
        if self._mad_salvata is not None:
            return self._mad_salvata
        if len(self.campioni) < 3:
            return 0.0
        m = self.mediana
        return statistics.median([abs(x - m) for x in self.campioni])

    def deviazioni(self, x: float) -> float:
        return (x - self.media) / self.pavimento

    def deviazioni_oltre_visto(self, x: float) -> float:
        return self.deviazioni_oltre(x, self.percentile_alto)

    def deviazioni_oltre(self, x: float, riferimento: float) -> float:
        if riferimento == -math.inf or self.minimo == math.inf:
            return self.deviazioni(x)
        if x <= riferimento:
            return 0.0
        return (x - riferimento) / self.pavimento

    def deviazioni_robuste(self, x: float) -> float:
        d = self.mad * 1.4826
        s = max(d, self.differenza_estremi, abs(self.mediana) * 0.02, EPS)
        return (x - self.mediana) / s

    def come_dict(self) -> dict[str, Any]:
        d = {"n": self.n, "media": self.media, "varianza": self.varianza,
             "minimo": None if self.minimo == math.inf else self.minimo,
             "massimo": None if self.massimo == -math.inf else self.massimo,
             "mediana": self.mediana, "mad": self.mad,
             "alto": self.percentile_alto}
        if self._conteggi_validi and self.conteggi:
            d["conteggi"] = {f"{k:g}": v for k, v in sorted(self.conteggi.items())}
        return d


@dataclass
class NormalityProfile:
    chiave: str = "senza-chiave"
    fissato: bool = False
    finestre: int = 0
    globale: dict[str, Statistica] = field(default_factory=dict)
    peer: dict[str, dict[str, Statistica]] = field(default_factory=dict)
    comandi_ammessi: set[str] = field(default_factory=set)
    coppie_ammesse: set[str] = field(default_factory=set)
    peer_noti: set[str] = field(default_factory=set)
    origine_di_identita: dict[str, str] = field(default_factory=dict)
    origine: dict[str, Any] = field(default_factory=dict)
    _ultimo_comando_per_peer: dict[str, str] = field(default_factory=dict)

    def apprendi(self, fv: FeatureVector) -> None:
        if self.fissato:
            return
        self.finestre += 1
        for nome, valore in fv.valori.items():
            self.globale.setdefault(nome, Statistica()).aggiorna(float(valore))
        for p, identita in fv.identita_per_peer.items():
            self.origine_di_identita.setdefault(identita, p)
        for p, voce in fv.per_peer.items():
            self.peer_noti.add(p)
            dest = self.peer.setdefault(p, {})
            for nome, valore in voce.items():
                if nome.startswith("cmd_"):
                    self.comandi_ammessi.add(nome[4:])
                    continue
                dest.setdefault(nome, Statistica()).aggiorna(float(valore))

    def apprendi_comando(self, peer: str, comando: str) -> None:
        if self.fissato:
            return
        self.comandi_ammessi.add(comando)
        self.peer_noti.add(peer)
        prec = self._ultimo_comando_per_peer.get(peer)
        if prec:
            self.coppie_ammesse.add(f"{prec}>{comando}")
        self._ultimo_comando_per_peer[peer] = comando

    def fissa(self) -> None:
        self.fissato = True

    @property
    def maturo(self) -> bool:
        return self.finestre >= MIN_CAMPIONI

    def stat(self, nome: str) -> Statistica | None:
        s = self.globale.get(nome)
        return s if s is not None and s.n >= MIN_CAMPIONI else None

    def stat_peer(self, peer: str, nome: str) -> Statistica | None:
        s = self.peer.get(peer, {}).get(nome)
        return s if s is not None and s.n >= MIN_CAMPIONI else None

    def peer_sconosciuto(self, peer: str) -> bool:
        return peer not in self.peer_noti

    def origine_attesa(self, identita: str) -> str | None:
        return self.origine_di_identita.get(identita)

    def salva(self, cartella: str | Path) -> Path:
        d = Path(cartella) / self.chiave
        d.mkdir(parents=True, exist_ok=True)
        from ids.parametri import GENERAZIONE
        contenuto = {
            "chiave": self.chiave,
            "generazione": GENERAZIONE,
            "grandezze": sorted(self.globale),
            "congelato": self.fissato,
            "finestre": self.finestre,
            "globale": {k: v.come_dict() for k, v in self.globale.items()},
            "peer": {p: {k: v.come_dict() for k, v in d2.items()}
                     for p, d2 in self.peer.items()},
            "comandi_ammessi": sorted(self.comandi_ammessi),
            "coppie_ammesse": sorted(self.coppie_ammesse),
            "peer_noti": sorted(self.peer_noti),
            "origine_di_identita": dict(sorted(self.origine_di_identita.items())),
            "origine": dict(self.origine),
        }
        f = d / "profilo.json"
        f.write_text(json.dumps(contenuto, indent=2, ensure_ascii=False), encoding="utf-8")
        return f

    @staticmethod
    def carica(percorso: str | Path) -> "NormalityProfile":
        d = json.loads(Path(percorso).read_text(encoding="utf-8"))
        prof = NormalityProfile(chiave=d.get("chiave", "senza-chiave"),
                                fissato=True, finestre=int(d.get("finestre", 0)))

        def ricrea(dd: dict[str, Any]) -> Statistica:
            s = Statistica(n=int(dd.get("n", 0)), media=float(dd.get("media", 0.0)),
                           varianza=float(dd.get("varianza", 0.0)))
            s.minimo = dd.get("minimo") if dd.get("minimo") is not None else math.inf
            s.massimo = dd.get("massimo") if dd.get("massimo") is not None else -math.inf
            mediana, mad = float(dd.get("mediana", s.media)), float(dd.get("mad", 0.0))
            s.campioni = [mediana - mad, mediana, mediana + mad]
            if dd.get("mediana") is not None:
                s._mediana_salvata = mediana
            if dd.get("mad") is not None:
                s._mad_salvata = mad
            if dd.get("alto") is not None:
                s._alto_salvato = float(dd["alto"])
            if dd.get("conteggi"):
                s.conteggi = {float(k): int(v) for k, v in dd["conteggi"].items()}
            else:
                s._conteggi_validi = False
            return s

        prof.globale = {k: ricrea(v) for k, v in d.get("globale", {}).items()}
        prof.peer = {p: {k: ricrea(v) for k, v in dd.items()}
                     for p, dd in d.get("peer", {}).items()}
        prof.comandi_ammessi = set(d.get("comandi_ammessi", []))
        prof.coppie_ammesse = set(d.get("coppie_ammesse", []))
        prof.peer_noti = set(d.get("peer_noti", []))
        prof.origine_di_identita = {str(k): str(v) for k, v
                                    in d.get("origine_di_identita", {}).items()}
        prof.origine = dict(d.get("origine", {}))
        if d.get("generazione") is not None:
            prof.origine.setdefault("generazione", d["generazione"])
        return prof


class ArchivioProfili:
    def __init__(self, radice: str | Path = "data/profiles") -> None:
        self.radice = Path(radice)
        self.radice.mkdir(parents=True, exist_ok=True)

    def percorso(self, chiave: str) -> Path:
        return self.radice / chiave / "profilo.json"

    def esiste(self, chiave: str) -> bool:
        return self.percorso(chiave).exists()

    def carica(self, chiave: str) -> NormalityProfile | None:
        f = self.percorso(chiave)
        if not f.exists():
            return None
        profilo = NormalityProfile.carica(f)
        if profilo.chiave != chiave:
            return None
        return profilo

    def deposita(self, profilo: NormalityProfile) -> Path:
        if not profilo.fissato:
            raise ValueError("profilo non fissato: deposito non consentito")
        if not profilo.maturo:
            raise ValueError(f"profilo immaturo: {profilo.finestre} finestre, "
                             f"minimo {MIN_CAMPIONI}")
        return profilo.salva(self.radice)

    def elenco(self) -> list[str]:
        return sorted(d.name for d in self.radice.iterdir()
                      if d.is_dir() and (d / "profilo.json").exists())

    def _segnaposto(self, chiave: str) -> Path:
        return self.radice / f"{chiave}.in-apprendimento"

    def in_apprendimento(self, chiave: str) -> dict | None:
        f = self._segnaposto(chiave)
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not _processo_vivo(int(d.get("pid") or 0)):
            try:
                f.unlink()
            except OSError:
                pass
            return None
        return d

    def prenota(self, chiave: str, run_id: str) -> None:
        for _ in range(2):
            altra = self.in_apprendimento(chiave)
            if altra is not None and altra.get("run_id") != run_id:
                raise ProfiloOccupato(chiave, altra)
            if altra is not None:
                return
            try:
                fd = os.open(self._segnaposto(chiave), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                continue
            with os.fdopen(fd, "w", encoding="utf-8") as h:
                json.dump({"run_id": run_id, "pid": os.getpid(), "inizio": time.time()}, h)
            return
        raise ProfiloOccupato(chiave, self.in_apprendimento(chiave) or {})

    def libera(self, chiave: str, run_id: str) -> None:
        d = self.in_apprendimento(chiave)
        if d is not None and d.get("run_id") == run_id:
            try:
                self._segnaposto(chiave).unlink()
            except OSError:
                pass


class ProfiloOccupato(RuntimeError):
    def __init__(self, chiave: str, altra: dict) -> None:
        super().__init__(
            f"profilo {chiave} in apprendimento nell'esecuzione "
            f"{altra.get('run_id', '?')}: apprendimento e riuso sospesi fino al "
            "termine")
        self.chiave = chiave
        self.altra = altra


def _processo_vivo(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
