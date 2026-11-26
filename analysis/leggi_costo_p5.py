from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

CONTROLLI = ("DM",)


def carica(percorso: Path) -> list[dict]:
    return [json.loads(r) for r in percorso.read_text(encoding="utf-8").splitlines()
            if r.strip()]


def e_controllo(riga: dict) -> bool:
    return not riga.get("con_attacco") or riga["nome"].split("-")[0] in CONTROLLI


def si_accende(voce: dict, controllo: bool) -> bool:
    if controllo:
        return voce["fuori"] > 0 or voce["rilevato"] is True
    return voce["fuori"] > 0


def tabella(righe: list[dict]) -> str:
    buoni = [r for r in righe if "errore" not in r]
    rotti = [r for r in righe if "errore" in r]
    attacchi = [r for r in buoni if not e_controllo(r)]
    controlli = [r for r in buoni if e_controllo(r)]
    soglie = list(buoni[0]["soglie"]) if buoni else []
    fuori = []
    fuori.append(f"esecuzioni lette: {len(buoni)}  (con attacco {len(attacchi)}, "
                 f"controlli {len(controlli)}, illeggibili {len(rotti)})")
    generazioni = collections.Counter(r.get("profilo_generazione") for r in buoni)
    riprodotti = collections.Counter(r.get("profilo_riprodotto") for r in buoni)
    fuori.append(f"generazioni dei profili: {dict(generazioni)}")
    fuori.append(f"riproduzione: {dict(riprodotti)}")
    fuori.append("")
    fuori.append(f"{'soglia':8s} {'rilevate dentro':>16s} {'attribuite':>11s} "
                 f"{'controlli accesi':>17s} {'confine':>8s} {'deriva':>7s} "
                 f"{'aperture fuori':>15s} {'latenza':>8s}")
    for s in soglie:
        dentro = [r for r in attacchi if r["soglie"][s]["rilevato"]]
        att = sum(1 for r in attacchi if r["soglie"][s]["attribuzione"] == "attribuita")
        accesi = [r for r in controlli if si_accende(r["soglie"][s], True)]
        perche = collections.Counter(r["soglie"][s].get("perche", "?")
                                     for r in accesi)
        lat = sorted(r["soglie"][s]["latenza_s"] for r in dentro
                     if r["soglie"][s]["latenza_s"] is not None)
        mediana = f"{lat[len(lat) // 2]:.1f}" if lat else "-"
        fuori.append(
            f"{s:8s} {f'{len(dentro)}/{len(attacchi)}':>16s} "
            f"{f'{att}/{len(attacchi)}':>11s} "
            f"{f'{len(accesi)}/{len(controlli)}':>17s} "
            f"{perche.get('confine', 0):>8d} {perche.get('deriva', 0):>7d} "
            f"{sum(1 for r in attacchi if si_accende(r['soglie'][s], False)):>15d} "
            f"{mediana:>8s}")
    for s in soglie:
        accesi = [r for r in controlli if si_accende(r["soglie"][s], True)]
        if accesi:
            fuori.append("")
            fuori.append(f"controlli accesi con soglia {s}:")
            for r in sorted(accesi, key=lambda r: -r["soglie"][s]["fuori"]):
                v = r["soglie"][s]
                dove = ("nella finestra dichiarata" if v["rilevato"]
                        else f"aperture {v['fuori']}")
                fuori.append(f"   {r['nome'][-40:]:42s} {dove:30s} "
                             f"{v.get('perche', '?') or '-':8s} "
                             f"livelli {v.get('livelli')}  "
                             f"profilo {str(r.get('profilo_proprietario'))[-4:]}")
    if rotti:
        fuori.append("")
        fuori.append("illeggibili:")
        for r in rotti:
            fuori.append(f"   {r['nome'][-40:]:42s} {r['errore'][:70]}")
    return "\n".join(fuori)


def confronto(a: list[dict], b: list[dict], nome_a: str, nome_b: str) -> str:
    per_nome_a = {r["nome"]: r for r in a if "errore" not in r}
    per_nome_b = {r["nome"]: r for r in b if "errore" not in r}
    comuni = sorted(set(per_nome_a) & set(per_nome_b))
    fuori = [f"confronto {nome_a} -> {nome_b}: {len(comuni)} esecuzioni in comune"]
    cambi = 0
    for nome in comuni:
        x, y = per_nome_a[nome], per_nome_b[nome]
        for s in x["soglie"]:
            vx, vy = x["soglie"][s], y["soglie"].get(s, {})
            diff = [f"{k}: {vx[k]} -> {vy.get(k)}"
                    for k in ("rilevato", "latenza_s", "fuori", "attribuzione")
                    if vx.get(k) != vy.get(k)]
            if diff:
                cambi += 1
                fuori.append(f"   {nome[-38:]:40s} soglia {s:5s} " + "; ".join(diff))
    if not cambi:
        fuori.append("   nessuna differenza")
    return "\n".join(fuori)


def main() -> None:
    ap = argparse.ArgumentParser(description="Tabella del costo della soglia P5")
    ap.add_argument("misure", nargs="+", type=Path,
                    help="file JSON Lines prodotti da analysis.costo_p5 --jsonl")
    args = ap.parse_args()
    caricate = [(m, carica(m)) for m in args.misure]
    for percorso, righe in caricate:
        print(f"=== {percorso.name}")
        print(tabella(righe))
        print()
    if len(caricate) == 2:
        (pa, a), (pb, b) = caricate
        print(confronto(a, b, pa.stem, pb.stem))


if __name__ == "__main__":
    main()
