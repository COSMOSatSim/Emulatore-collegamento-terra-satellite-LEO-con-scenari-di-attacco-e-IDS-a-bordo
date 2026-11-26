from __future__ import annotations

import argparse
import json
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path


def analizza_riepilogo_tcpdump(testo: str) -> dict[str, int]:
    valori: dict[str, int] = {}
    mappa = {"captured": "catturati", "received by filter": "ricevuti",
             "dropped by kernel": "persi", "dropped by interface": "persi_interfaccia"}
    for riga in testo.splitlines():
        riga = riga.strip()
        m = re.match(r"^(\d+)\s+packets?\s+(.+?)\.?$", riga)
        if not m:
            continue
        chiave = mappa.get(m.group(2).strip())
        if chiave:
            valori[chiave] = int(m.group(1))
    return valori


DIMENSIONE_CATTURA = 0


class DomainTap:
    def __init__(self, interfaccia: str, uscita: str | Path,
                 filtro: str = "tcp",
                 dimensione_massima: int = DIMENSIONE_CATTURA) -> None:
        self.interfaccia = interfaccia
        self.uscita = Path(uscita)
        self.uscita.parent.mkdir(parents=True, exist_ok=True)
        self.filtro = filtro
        self.dimensione_massima = dimensione_massima
        self._proc: subprocess.Popen | None = None
        self.riepilogo: dict[str, int] = {}

    @property
    def disponibile(self) -> bool:
        return shutil.which("tcpdump") is not None

    BUFFER_KIB = 65536

    def comando(self) -> list[str]:
        cmd = ["tcpdump", "-i", self.interfaccia, "-n", "-B", str(self.BUFFER_KIB),
               "-s", str(self.dimensione_massima), "-w", str(self.uscita)]
        if self.filtro:
            cmd.append(self.filtro)
        return cmd

    def avvia(self) -> bool:
        if not self.disponibile:
            return False
        cmd = self.comando()
        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE, text=True)
        return True

    def ferma(self) -> None:
        if self._proc is None:
            return
        self._proc.terminate()
        try:
            _out, err = self._proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            _out, err = self._proc.communicate()
        self.riepilogo = analizza_riepilogo_tcpdump(err or "")
        self._proc = None

    @property
    def pacchetti_persi(self) -> int | None:
        if not self.riepilogo:
            return None
        return self.riepilogo.get("persi", 0) + self.riepilogo.get("persi_interfaccia", 0)

    @property
    def completo(self) -> bool | None:
        persi = self.pacchetti_persi
        return None if persi is None else persi == 0


class GlobalObserver:
    def __init__(self, interfacce: list[str], cartella: str | Path) -> None:
        self.cartella = Path(cartella)
        self.taps = [DomainTap(i, self.cartella / f"{i}.pcap") for i in interfacce]
        self._attivo = True

    def avvia(self) -> dict:
        esiti = {}
        for t in self.taps:
            esiti[t.interfaccia] = t.avvia()
        indice = {"avvio": time.time(), "interfacce": esiti,
                  "nota": "false: tcpdump non disponibile"}
        (self.cartella / "indice.json").write_text(
            json.dumps(indice, indent=2, ensure_ascii=False), encoding="utf-8")
        return indice

    def ferma(self, *_: object) -> None:
        self._attivo = False
        for t in self.taps:
            t.ferma()
        self._scrivi_indice()

    def _scrivi_indice(self) -> None:
        dettaglio = {t.interfaccia: {"riepilogo": t.riepilogo,
                                     "pacchetti_persi": t.pacchetti_persi,
                                     "completo": t.completo}
                     for t in self.taps}
        completi = [t.completo for t in self.taps if t.completo is not None]
        indice = {"chiusura": time.time(), "interfacce": dettaglio,
                  "cattura_integra": all(completi) if completi else None}
        try:
            (self.cartella / "indice.json").write_text(
                json.dumps(indice, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass

    @property
    def cattura_integra(self) -> bool | None:
        completi = [t.completo for t in self.taps if t.completo is not None]
        return all(completi) if completi else None

    def esegui(self, durata: float | None = None) -> None:
        self.avvia()
        inizio = time.time()
        while self._attivo:
            if durata is not None and time.time() - inizio >= durata:
                break
            time.sleep(1.0)
        self.ferma()


def main() -> None:
    ap = argparse.ArgumentParser(description="Osservatore globale")
    ap.add_argument("--interfaccia", action="append", default=None,
                    help="interfaccia da catturare, ripetibile; predefinita eth0")
    ap.add_argument("--uscita", required=True, help="file o cartella di destinazione")
    ap.add_argument("--durata", type=float, default=None,
                    help="durata della cattura, s; senza valore fino all'arresto")
    args = ap.parse_args()

    interfacce = args.interfaccia or ["eth0"]
    cartella = Path(args.uscita)
    if cartella.suffix:
        cartella = cartella.parent
    osservatore = GlobalObserver(interfacce, cartella)
    signal.signal(signal.SIGTERM, osservatore.ferma)
    signal.signal(signal.SIGINT, osservatore.ferma)
    osservatore.esegui(args.durata)


if __name__ == "__main__":
    main()
