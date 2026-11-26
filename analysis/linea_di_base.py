from __future__ import annotations

import argparse
import csv
import gzip
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator

from ids.fusion import GIU, SU

GRANDEZZE_DA_VALUTARE = ("pacchetti_s", "comandi_s", "sessioni_aperte",
             "nuove_connessioni_s", "segmenti_in_s", "ritrasmessi_s")

DENTRO = ("attacco", "osservazione")


def righe(f: Path) -> Iterator[dict[str, str]]:
    apri = gzip.open if f.suffix == ".gz" else open
    with apri(f, "rt", encoding="utf-8", newline="") as ingresso:
        yield from csv.DictReader(ingresso)


def _numero(x: Any) -> float | None:
    try:
        return None if x in ("", None) else float(x)
    except (TypeError, ValueError):
        return None


def recinto_alto(valori: list[float]) -> float | None:
    puliti = sorted(valori)
    if len(puliti) < 8:
        return None
    q1, _, q3 = statistics.quantiles(puliti, n=4)
    return q3 + 1.5 * (q3 - q1)


def valuta_grandezza(finestre: list[tuple[float, str, float]],
                     grandezza: str, soglia: float | None = None) -> dict[str, Any]:
    if soglia is None:
        soglia = recinto_alto([v for _, fase, v in finestre if fase == "nominale"])
    if soglia is None:
        return {"grandezza": grandezza, "giudicabile": False}
    sopra = sotto = 0
    in_allarme = False
    aperture_dentro: list[float] = []
    aperture_fuori = 0
    for t, fase, v in finestre:
        if fase == "nominale":
            continue
        if v > soglia:
            sopra, sotto = sopra + 1, 0
        else:
            sopra, sotto = 0, sotto + 1
        if not in_allarme and sopra >= SU:
            in_allarme = True
            if fase in DENTRO:
                aperture_dentro.append(t)
            else:
                aperture_fuori += 1
        elif in_allarme and sotto >= GIU:
            in_allarme = False
    return {"grandezza": grandezza, "giudicabile": True, "soglia": round(soglia, 4),
            "aperture_dentro": len(aperture_dentro), "aperture_fuori": aperture_fuori,
            "primo_dentro": min(aperture_dentro) if aperture_dentro else None}


def per_esecuzione(cartelle: list[Path]) -> dict[str, list[tuple[float, str, dict]]]:
    dati: dict[str, list] = defaultdict(list)
    for cartella in cartelle:
        for r in righe(cartella / "finestre.csv.gz"):
            dati[r.get("esecuzione", "?")].append(
                (_numero(r.get("t")) or 0.0, r.get("fase", ""), r))
    return dati


def chiavi_di_profilo(cartelle: list[Path]) -> dict[str, str]:
    fuori: dict[str, str] = {}
    for cartella in cartelle:
        f = cartella / "esecuzioni.csv"
        if f.exists():
            for r in righe(f):
                fuori[r.get("esecuzione", "?")] = r.get("chiave_profilo", "")
    return fuori


def soglie_per_chiave(dati: dict[str, list], chiavi: dict[str, str]
                      ) -> dict[tuple[str, str], float]:
    campioni: dict[tuple[str, str], list[float]] = defaultdict(list)
    for nome, v in dati.items():
        chiave = chiavi.get(nome, "")
        for _, fase, r in v:
            if fase != "nominale":
                continue
            for grandezza in GRANDEZZE_DA_VALUTARE:
                x = _numero(r.get(grandezza))
                if x is not None:
                    campioni[(chiave, grandezza)].append(x)
    fuori: dict[tuple[str, str], float] = {}
    for k, valori in campioni.items():
        soglia = recinto_alto(valori)
        if soglia is not None:
            fuori[k] = soglia
    return fuori


def valuta(cartelle: list[Path]) -> dict[str, Any]:
    dati = per_esecuzione(cartelle)
    chiavi = chiavi_di_profilo(cartelle)
    soglie = soglie_per_chiave(dati, chiavi)
    con_attacco = {n: v for n, v in dati.items()
                   if any(fase in DENTRO for _, fase, _ in v)}
    quiete = {n: v for n, v in dati.items() if n not in con_attacco}
    esito: dict[str, Any] = {"esecuzioni": len(dati), "con_attacco": len(con_attacco),
                             "quiete": len(quiete), "per_grandezza": {}}
    for grandezza in GRANDEZZE_DA_VALUTARE:
        rilevate = giudicabili = 0
        falsi = 0
        latenze: list[float] = []
        for nome, v in con_attacco.items():
            finestre = [(t, fase, _numero(r.get(grandezza))) for t, fase, r in v]
            finestre = [(t, f, x) for t, f, x in finestre if x is not None]
            if not finestre:
                continue
            e = valuta_grandezza(finestre, grandezza,
                                 soglie.get((chiavi.get(nome, ""), grandezza)))
            if not e["giudicabile"]:
                continue
            giudicabili += 1
            if e["aperture_dentro"]:
                rilevate += 1
            falsi += e["aperture_fuori"]
        falsi_quieti = 0
        for nome, v in quiete.items():
            finestre = [(t, fase, _numero(r.get(grandezza))) for t, fase, r in v]
            finestre = [(t, f, x) for t, f, x in finestre if x is not None]
            if not finestre:
                continue
            e = valuta_grandezza(finestre, grandezza,
                                 soglie.get((chiavi.get(nome, ""), grandezza)))
            if e["giudicabile"]:
                falsi_quieti += e["aperture_fuori"] + e["aperture_dentro"]
        esito["per_grandezza"][grandezza] = {
            "esecuzioni_giudicabili": giudicabili, "rilevate": rilevate,
            "aperture_fuori_finestra": falsi,
            "aperture_nelle_quiete": falsi_quieti}
    return esito


def stampa(esito: dict[str, Any]) -> str:
    parti = [f"esecuzioni: {esito['esecuzioni']} "
             f"({esito['con_attacco']} con attacco, {esito['quiete']} quiete)",
             "",
             f"{'grandezza':22s} {'rilevate':>12s} {'fuori finestra':>15s} "
             f"{'nelle quiete':>13s}"]
    for nome, v in esito["per_grandezza"].items():
        parti.append(f"{nome:22s} {v['rilevate']:5d}/{v['esecuzioni_giudicabili']:<6d} "
                     f"{v['aperture_fuori_finestra']:15d} {v['aperture_nelle_quiete']:13d}")
    return "\n".join(parti)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Linea di base: upper fence di Tukey con isteresi")
    ap.add_argument("cartelle", nargs="+", type=Path, help="serie esportate da analysis.dataset")
    ap.add_argument("--uscita", type=Path, default=None,
                    help="cartella di linea-di-base.json e .txt")
    args = ap.parse_args()
    esito = valuta(args.cartelle)
    testo = stampa(esito)
    print(testo)
    if args.uscita:
        args.uscita.mkdir(parents=True, exist_ok=True)
        (args.uscita / "linea-di-base.json").write_text(
            json.dumps(esito, indent=2, ensure_ascii=False), encoding="utf-8")
        (args.uscita / "linea-di-base.txt").write_text(testo, encoding="utf-8")
        print(f"\nscritto in {args.uscita}")


if __name__ == "__main__":
    main()
