from __future__ import annotations

import argparse
import collections
import json
import statistics
from pathlib import Path
from typing import Any

from analysis.dataset import leggi_configurazione_fissata

SERIE = ("dataset-2026-10-27-10cdfce", "n2-4pct-2026-10-27-10cdfce")

TRASPORTO = "P-BBR"

RAMI: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sessioni", ("D1",)), ("comandi", ("D2",)), ("memoria", ("D3",)),
    ("sessioni lente", ("D4",)), ("inondazione", ("DF",)),
    ("identità presa in prestito", ("SP",)), ("replay di comandi", ("RP",)),
    ("percorso di caricamento", ("MI",)), ("verifica e modifica", ("MD",)),
    ("senza attacco", ("S0",)),
)


def ramo_di(nome: str) -> str:
    fam = nome.split("-")[0]
    for etichetta, prefissi in RAMI:
        if fam in prefissi:
            return etichetta
    return f"ramo non noto ({fam})"


def carica(cartella: Path) -> list[dict[str, Any]]:
    fuori: list[dict[str, Any]] = []
    for f in sorted(cartella.glob("*.json")):
        fuori += json.loads(f.read_text(encoding="utf-8"))
    return fuori


def anagrafica(radice: Path, serie: tuple[str, ...] = SERIE) -> dict[str, dict]:
    cong = leggi_configurazione_fissata(radice / "piani" / "configurazione-fissata.txt")
    fuori: dict[str, dict] = {}
    for s in serie:
        for f in sorted((radice / "risultati" / s).glob("*/metriche.json")):
            m = json.loads(f.read_text(encoding="utf-8"))["esecuzioni"][0]
            d = json.loads((f.parent / "run.json").read_text(encoding="utf-8"))
            seme = d.get("seme")
            fuori[m["run_id"]] = {
                "trasporto": m["trasporto"], "con_attacco": m["con_attacco"],
                "seme": seme,
                "valutazione": seme in cong["semi"]
                and m.get("generazione") == cong["generazione"]}
    return fuori


def _mediana(valori: list[float]) -> str:
    return f"{statistics.median(valori):.1f} s" if valori else "-"


def tabelle(righe: list[dict], info: dict[str, dict],
            completa: str = "completa") -> str:
    per: dict[str, dict[str, dict]] = collections.defaultdict(dict)
    for r in righe:
        per[r["configurazione"]][r["esecuzione"]] = r
    manca = sorted(set(per[completa]) - set(info))
    if manca:
        raise ValueError(f"esecuzioni senza anagrafica: {manca[:3]}")
    c = per[completa]
    tutte = set(c)
    attacco = {n for n in tutte if info[n]["con_attacco"]}
    quiete = tutte - attacco
    val = {n for n in tutte
           if info[n]["valutazione"] and info[n]["trasporto"] == TRASPORTO}
    vala = {n for n in val if info[n]["con_attacco"]}
    presi = [n for n in vala if c[n]["rilevato"]]
    lat = [c[n]["latenza_s"] for n in presi if c[n]["latenza_s"] is not None]
    f = [f"esiti {len(righe)}   esecuzioni {len(tutte)}   "
         f"(con attacco {len(attacco)}, quiete {len(quiete)})",
         f"configurazioni: {list(per)}", "",
         "=== generazione in vigore",
         f"falsi positivi, {len(tutte)} esecuzioni: "
         f"{sum(c[n]['falsi_positivi'] for n in tutte)}",
         f"falsi allarmi nelle {len(quiete)} esecuzioni senza attacco: "
         f"{sum(1 for n in quiete if c[n]['falsi_positivi'] > 0)}",
         f"attacchi rilevati, {len(attacco)} con attacco: "
         f"{sum(1 for n in attacco if c[n]['rilevato'])}",
         f"attribuiti all'attaccante: "
         f"{sum(1 for n in attacco if c[n]['attribuzione'] == 'attribuita')}",
         f"insieme di valutazione {TRASPORTO}: {len(val)} esecuzioni, {len(vala)} "
         f"attacchi -> rilevati {len(presi)}, falsi positivi "
         f"{sum(c[n]['falsi_positivi'] for n in val)}",
         f"latenza mediana sull'insieme di valutazione: {_mediana(lat)}", ""]
    suo = {n for n in tutte if info[n]["trasporto"] == TRASPORTO}
    attb = {n for n in suo if info[n]["con_attacco"]}
    f.append(f"=== per ramo, {len(suo)} esecuzioni con {TRASPORTO} "
             f"({len(attb)} con attacco)")
    for etichetta, _ in RAMI:
        suoi = {n for n in suo if ramo_di(n) == etichetta}
        if not suoi:
            continue
        att = suoi & attb
        if not att:
            aperture = sum(c[n]["falsi_positivi"] for n in suoi)
            f.append(f"|{etichetta}|{len(suoi)}|-|"
                     f"{'nessun allarme' if not aperture else f'{aperture} aperture'}|")
            continue
        p = [n for n in att if c[n]["rilevato"]]
        f.append(f"|{etichetta}|{len(att)}|{len(p)}/{len(att)}|"
                 f"{_mediana([c[n]['latenza_s'] for n in p if c[n]['latenza_s'] is not None])}|")
    f.append("")
    f.append(f"=== ablazione, {len(attb)} esecuzioni con attacco e {TRASPORTO}")
    for conf, x in per.items():
        p = [n for n in attb if x[n]["rilevato"]]
        persi = collections.Counter(ramo_di(n) for n in attb if not x[n]["rilevato"])
        f.append(
            f"|{conf}|{len(p)}/{len(attb)}|"
            f"{sum(1 for n in attb if x[n]['attribuzione'] == 'attribuita')}/{len(attb)}|"
            f"{sum(1 for n in suo - attb if x[n]['falsi_positivi'] > 0)}|"
            f"{_mediana([x[n]['latenza_s'] for n in p if x[n]['latenza_s'] is not None])}|"
            f"{', '.join(f'{k} ({v})' for k, v in sorted(persi.items())) or '-'}|")
    allarme = sum(c[n]["finestre_allarme"] for n in tutte)
    att_in = sum(c[n]["finestre_attaccante_in_allarme"] for n in tutte)
    senza = sum(c[n]["finestre_senza_entita"] for n in tutte)
    cat = collections.Counter(c[n]["attribuzione_per_entita"] for n in attacco)
    coacc = sum(1 for n in attacco if [e for e in c[n]["entita_aperte"]
                                       if e not in ("globale", "10.0.0.40")])
    f += ["", f"=== finestre e attribuzione, {len(tutte)} esecuzioni",
          f"finestre d'allarme {allarme}, attaccante in allarme {att_in} "
          f"({att_in / allarme:.1%}), senza entità in allarme {senza} "
          f"({senza / allarme:.1%})",
          f"per entità, {len(attacco)} esecuzioni con attacco: "
          f"{dict(sorted(cat.items()))}",
          f"coattribuzioni: {coacc} esecuzioni con almeno un'entità legittima "
          f"in allarme"]
    return "\n".join(f)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Tabelle delle rivalutazioni fuori linea delle 70 esecuzioni")
    ap.add_argument("grezzi", type=Path, help="cartella dei grezzi dell'ablazione")
    ap.add_argument("--radice", type=Path, default=Path(__file__).resolve().parents[1],
                    help="radice del repository")
    args = ap.parse_args()
    print(tabelle(carica(args.grezzi), anagrafica(args.radice)))


if __name__ == "__main__":
    main()
