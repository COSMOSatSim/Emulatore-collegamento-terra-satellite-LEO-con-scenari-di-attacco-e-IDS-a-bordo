from __future__ import annotations

import argparse
import random
import subprocess
import time
from typing import Iterator

from common.andamento_rtt import FORME as FORME_ANDAMENTO
from common.andamento_rtt import RISOLUZIONE_MS, comando, fattore, quantizza

ANCORA_S = 12.0
DURATA_PREDEFINITA_S = 900.0

CASUALE = "casuale"
FORME = (*FORME_ANDAMENTO, CASUALE)
FORMA_PREDEFINITA = "u"
PASSO_S = 1.0


def inizio_passaggio(adesso: float, durata_s: float) -> float:
    if durata_s <= 0:
        raise ValueError(f"durata del passaggio non positiva: {durata_s}")
    return adesso - ((adesso - ANCORA_S) % durata_s)


def prossimo_cambio(adesso: float, durata_s: float) -> float:
    return inizio_passaggio(adesso, durata_s) + durata_s


def ritardo_nel_passaggio(forma: str, minimo_ms: float, massimo_ms: float,
                          adesso: float, durata_s: float) -> float:
    posizione = (adesso - inizio_passaggio(adesso, durata_s)) / durata_s
    return round(minimo_ms + (massimo_ms - minimo_ms) * fattore(forma, posizione), 3)


def ritardi(seme: int, minimo_ms: float, massimo_ms: float,
            quanti: int) -> list[float]:
    caso = random.Random(seme)
    if massimo_ms <= minimo_ms:
        return [minimo_ms] * quanti
    return [round(caso.uniform(minimo_ms, massimo_ms), 3) for _ in range(quanti)]


def successione(seme: int, minimo_ms: float, massimo_ms: float) -> Iterator[float]:
    caso = random.Random(seme)
    while True:
        if massimo_ms <= minimo_ms:
            yield minimo_ms
        else:
            yield round(caso.uniform(minimo_ms, massimo_ms), 3)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Ritardo del nodo lungo i passaggi successivi dei satelliti")
    ap.add_argument("--modello", required=True,
                    help="comando tc con {ritardo} al posto del ritardo")
    ap.add_argument("--minimo-ms", type=float, required=True,
                    help="ritardo minimo, a metà del passaggio, ms")
    ap.add_argument("--massimo-ms", type=float, required=True,
                    help="ritardo massimo, all'inizio e alla fine del passaggio, ms")
    ap.add_argument("--durata-s", type=float, default=DURATA_PREDEFINITA_S,
                    help="durata di un passaggio del satellite, s")
    ap.add_argument("--forma", choices=FORME, default=FORMA_PREDEFINITA,
                    help="andamento nel passaggio: u quadratico, v lineare o casuale")
    ap.add_argument("--risoluzione-ms", type=float, default=RISOLUZIONE_MS,
                    help="passo dei ritardi delle forme u e v, ms")
    ap.add_argument("--seme", type=int, default=0,
                    help="seme della successione dei ritardi della forma casuale")
    ap.add_argument("--vista", default=None,
                    help="vista locale del nodo per annotare i cambi")
    args = ap.parse_args()
    if args.durata_s <= 0:
        ap.error("--durata-s deve essere positiva")

    bus = None
    if args.vista:
        from model.events import NODO_CANALE, EventLog
        bus = EventLog(args.vista)

    def applica(ritardo: float) -> None:
        esito = subprocess.run(comando(args.modello, ritardo), shell=True,
                               capture_output=True, text=True)
        if bus is not None:
            bus.scrivi(NODO_CANALE, {
                "evento": "riconfigurazione", "forma": args.forma, "ritardo_ms": ritardo,
                "durata_passaggio_s": args.durata_s,
                "esito": "applicato" if esito.returncode == 0 else "fallito",
                "motivo": esito.stderr.strip()[-200:] if esito.returncode else ""})

    try:
        if args.forma == CASUALE:
            prossimi = successione(args.seme, args.minimo_ms, args.massimo_ms)
            while True:
                attesa = prossimo_cambio(time.time(), args.durata_s) - time.time()
                if attesa > 0:
                    time.sleep(attesa)
                applica(next(prossimi))
        applicato: float | None = None
        while True:
            ritardo = quantizza(
                ritardo_nel_passaggio(args.forma, args.minimo_ms, args.massimo_ms,
                                      time.time(), args.durata_s),
                args.risoluzione_ms, args.minimo_ms, args.massimo_ms)
            if ritardo != applicato:
                applica(ritardo)
                applicato = ritardo
            time.sleep(PASSO_S)
    except KeyboardInterrupt:
        pass
    finally:
        if bus is not None:
            bus.chiudi()


if __name__ == "__main__":
    main()
