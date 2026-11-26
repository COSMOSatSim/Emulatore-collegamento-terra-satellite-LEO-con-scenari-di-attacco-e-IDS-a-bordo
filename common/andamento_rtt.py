from __future__ import annotations

import argparse
import subprocess
import time
from typing import Iterable

from common.visibilita import Finestra, Visibilita

FORME = ("v", "u")
PASSO_S = 1.0
RISOLUZIONE_MS = 0.5


def comando(modello: str, ritardo_ms: float) -> str:
    if "{ritardo}" not in modello:
        raise ValueError("il modello non contiene {ritardo}")
    return modello.format(ritardo=f"{ritardo_ms:g}")


def fattore(forma: str, posizione: float) -> float:
    if forma not in FORME:
        raise ValueError(f"andamento dell'RTT sconosciuto: {forma}")
    distanza = abs(2.0 * min(1.0, max(0.0, posizione)) - 1.0)
    return distanza if forma == "v" else distanza * distanza


def ritardo_in_finestra(forma: str, minimo_ms: float, massimo_ms: float,
                        finestre: Iterable[Finestra], t: float) -> float:
    finestre = tuple(finestre)
    if not finestre:
        return round(minimo_ms, 3)
    for f in finestre:
        if f.inizio <= t <= f.fine:
            posizione = (t - f.inizio) / (f.fine - f.inizio)
            return round(minimo_ms + (massimo_ms - minimo_ms) * fattore(forma, posizione), 3)
    return round(massimo_ms, 3)


def quantizza(ritardo_ms: float, risoluzione_ms: float, minimo_ms: float,
              massimo_ms: float) -> float:
    if risoluzione_ms > 0:
        ritardo_ms = round(ritardo_ms / risoluzione_ms) * risoluzione_ms
    return round(min(massimo_ms, max(minimo_ms, ritardo_ms)), 3)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Ritardo della stazione nella finestra di visibilità")
    ap.add_argument("--modello", required=True,
                    help="comando tc con {ritardo} al posto del ritardo")
    ap.add_argument("--stazione", required=True,
                    help="nome della stazione nel calendario dei passaggi")
    ap.add_argument("--visibilita", required=True, help="file del calendario dei passaggi")
    ap.add_argument("--forma", choices=FORME, required=True,
                    help="andamento nella finestra: v lineare, u quadratico")
    ap.add_argument("--minimo-ms", type=float, required=True,
                    help="ritardo al centro della finestra, ms")
    ap.add_argument("--massimo-ms", type=float, required=True,
                    help="ritardo ai bordi e fuori dalle finestre, ms")
    ap.add_argument("--risoluzione-ms", type=float, default=RISOLUZIONE_MS,
                    help="passo dei ritardi applicati, ms")
    ap.add_argument("--vista", default=None, help="vista locale del nodo per annotare i cambi")
    args = ap.parse_args()

    bus = None
    if args.vista:
        from model.events import NODO_CANALE, EventLog
        bus = EventLog(args.vista)

    visibilita = Visibilita.da_file(args.visibilita)
    applicato: float | None = None
    try:
        while True:
            if visibilita.dichiarata:
                ritardo = quantizza(
                    ritardo_in_finestra(args.forma, args.minimo_ms, args.massimo_ms,
                                        visibilita.finestre_di(args.stazione), time.time()),
                    args.risoluzione_ms, args.minimo_ms, args.massimo_ms)
                if ritardo != applicato:
                    esito = subprocess.run(comando(args.modello, ritardo), shell=True,
                                           capture_output=True, text=True)
                    applicato = ritardo
                    if bus is not None:
                        bus.scrivi(NODO_CANALE, {
                            "evento": "andamento_rtt", "forma": args.forma,
                            "ritardo_ms": ritardo,
                            "esito": "applicato" if esito.returncode == 0 else "fallito",
                            "motivo": esito.stderr.strip()[-200:] if esito.returncode else ""})
            time.sleep(PASSO_S)
    except KeyboardInterrupt:
        pass
    finally:
        if bus is not None:
            bus.chiudi()


if __name__ == "__main__":
    main()
