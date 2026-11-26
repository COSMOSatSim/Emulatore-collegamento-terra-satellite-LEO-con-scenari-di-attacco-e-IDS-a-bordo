from __future__ import annotations

import argparse
import collections
import json
import re
import statistics
from pathlib import Path
from typing import Any

ATTACCANTE = "10.0.0.40"

GLOBALE = "globale"

IP = re.compile(r"\b10\.0\.0\.\d+\b")

CONTROLLI = ("DM", "S0")

NOMI_PRECEDENTI = {
    "oggi": "riferimento",
    "(d) coppia senza indirizzo": "coppia senza indirizzo",
    "3.1 massimo per sessioni": "massimo per sessioni",
    "tutte e due": "entrambi",
}


def carica(percorsi: list[Path]) -> list[dict[str, Any]]:
    fuori: list[dict[str, Any]] = []
    for p in sorted(percorsi):
        fuori += json.loads(p.read_text(encoding="utf-8"))
    return fuori


def nomi_attuali(righe: list[dict]) -> list[dict]:
    return [r | {"configurazione": NOMI_PRECEDENTI.get(r["configurazione"],
                                                     r["configurazione"])}
            for r in righe]


def per_configurazione(righe: list[dict]) -> dict[str, dict[str, dict]]:
    fuori: dict[str, dict[str, dict]] = collections.defaultdict(dict)
    for r in righe:
        fuori[r["configurazione"]][r["esecuzione"]] = r
    return dict(fuori)


def famiglia(nome: str) -> str:
    return nome.split("-")[0]


def e_controllo(nome: str) -> bool:
    return famiglia(nome) in CONTROLLI


def nomi_legittimi(esito: dict) -> collections.Counter:
    fuori: collections.Counter = collections.Counter()
    for k in esito.get("segnali_in_finestra") or ():
        m = IP.search(k)
        if not m or m.group(0) == ATTACCANTE:
            continue
        causa = k.split(":")[-1] if ":" in k else k.split("/")[-1]
        fuori[f'{k.split("/")[0]}:{causa}'] += 1
    return fuori


def coattribuite(esito: dict) -> list[str]:
    return [e for e in esito.get("entita_aperte") or ()
            if e not in (GLOBALE, ATTACCANTE)]


def differenze(a: dict, b: dict, campi: tuple[str, ...]) -> list[str]:
    return [f"{c}: {a.get(c)} -> {b.get(c)}" for c in campi if a.get(c) != b.get(c)]


CAMPI_CONTROLLO = ("rilevato", "latenza_s", "falsi_positivi", "attribuzione",
                   "attribuzione_per_entita", "latenza_attribuzione_s",
                   "latenza_attribuzione_entita_s", "entita_aperte",
                   "segnali_in_finestra", "finestre_allarme",
                   "finestre_attaccante_in_allarme")


def tabella(righe: list[dict], ordine: list[str] | None = None) -> str:
    per = per_configurazione(righe)
    ordine = ordine or list(per)
    esecuzioni = {r["esecuzione"] for r in righe}
    attacchi = {e for e in esecuzioni if not e_controllo(e)}
    controlli = esecuzioni - attacchi
    fuori = [f"esiti {len(righe)}   esecuzioni {len(esecuzioni)}   "
             f"(con attacco {len(attacchi)}, controlli {len(controlli)})",
             f"configurazioni: {dict((c, len(per[c])) for c in ordine)}", ""]
    fuori.append(f"{'configurazione':28s} {'rilevate':>9s} {'attrib.nomi':>12s} "
                 f"{'attrib.entità':>14s} {'controlli':>10s} {'lat.mediana':>12s} "
                 f"{'coattrib.':>9s} {'nomi leg.':>10s}")
    for c in ordine:
        suoi = per[c]
        presi = [n for n in attacchi if suoi[n]["rilevato"]]
        lat = [suoi[n]["latenza_s"] for n in presi if suoi[n]["latenza_s"] is not None]
        na = sum(1 for n in attacchi if suoi[n]["attribuzione"] == "attribuita")
        ne = sum(1 for n in attacchi
                 if suoi[n].get("attribuzione_per_entita") == "attribuita")
        acc = sum(1 for n in controlli
                  if suoi[n]["rilevato"] or suoi[n]["falsi_positivi"] > 0)
        co = sum(1 for n in attacchi if coattribuite(suoi[n]))
        leg = sum(1 for n in esecuzioni if nomi_legittimi(suoi[n]))
        med = f"{statistics.median(lat):.3f}" if lat else "-"
        fuori.append(
            f"{c:28s} {f'{len(presi)}/{len(attacchi)}':>9s} "
            f"{f'{na}/{len(attacchi)}':>12s} {f'{ne}/{len(attacchi)}':>14s} "
            f"{f'{acc}/{len(controlli)}':>10s} {med:>12s} "
            f"{f'{co}/{len(attacchi)}':>9s} {leg:>10d}")
    fuori.append("")
    fuori.append("cause dei nomi legittimi (controlli compresi); ultima riga: solo attacchi")
    conti = {c: collections.Counter() for c in ordine}
    conti_att = {c: collections.Counter() for c in ordine}
    for c in ordine:
        for n in esecuzioni:
            x = nomi_legittimi(per[c][n])
            conti[c].update(x)
            if n in attacchi:
                conti_att[c].update(x)
    cause = sorted({k for c in ordine for k in conti[c]})
    fuori.append(f"{'causa':42s} " + "".join(f"{c[:13]:>15s}" for c in ordine))
    for causa in cause:
        fuori.append(f"{causa:42s} " + "".join(f"{conti[c][causa]:>15d}" for c in ordine))
    fuori.append(f"{'(solo i ' + str(len(attacchi)) + ' attacchi)':42s} "
                 + "".join(f"{sum(conti_att[c].values()):>15d}" for c in ordine))
    fuori.append("")
    fuori.append("coattribuzioni per entità, per famiglia:")
    for c in ordine:
        fam: collections.Counter = collections.Counter()
        for n in attacchi:
            if coattribuite(per[c][n]):
                fam[famiglia(n)] += 1
        fuori.append(f"   {c:28s} {dict(sorted(fam.items()))}")
    return "\n".join(fuori)


def controllo_neutro(righe: list[dict], viva: str, controllo: str) -> str:
    per = per_configurazione(righe)
    a, b = per.get(viva, {}), per.get(controllo, {})
    comuni = sorted(set(a) & set(b))
    diff = [(n, d) for n in comuni
            for d in [differenze(a[n], b[n], CAMPI_CONTROLLO)] if d]
    fuori = [f"controllo di neutralità: '{viva}' contro '{controllo}', "
             f"{len(comuni)} esecuzioni, {len(CAMPI_CONTROLLO)} campi"]
    if not diff:
        fuori.append("   nessuna differenza")
    for n, d in diff[:10]:
        fuori.append(f"   {n[-38:]:40s} " + "; ".join(d))
    return "\n".join(fuori)


def cambi(righe: list[dict], base: str) -> str:
    per = per_configurazione(righe)
    campi = ("rilevato", "latenza_s", "attribuzione", "attribuzione_per_entita",
             "falsi_positivi", "entita_aperte")
    fuori = []
    for c in per:
        if c == base:
            continue
        conto: collections.Counter = collections.Counter()
        esempi = []
        for n in per[base]:
            for d in differenze(per[base][n], per[c][n], campi):
                conto[d.split(":")[0]] += 1
                if len(esempi) < 4:
                    esempi.append(f"{n[-30:]} {d}")
            if nomi_legittimi(per[base][n]) != nomi_legittimi(per[c][n]):
                conto["nomi legittimi"] += 1
        fuori.append(f"-- {c}: {dict(conto) if conto else 'nessuna differenza'}")
        fuori += [f"     {e}" for e in esempi]
    return "\n".join(fuori)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Tabelle della rivalutazione fuori linea dei parametri di decisione")
    ap.add_argument("grezzi", nargs="+", type=Path, help="file JSON dei grezzi dell'ablazione")
    ap.add_argument("--base", default="riferimento",
                    help="configurazione di riferimento")
    ap.add_argument("--viva", default="entrambi",
                    help="configurazione con tutti i parametri di decisione attivi")
    ap.add_argument("--controllo", default="controllo (vivo)",
                    help="configurazione vuota di controllo, attesa identica a --viva")
    args = ap.parse_args()
    righe = nomi_attuali(carica(args.grezzi))
    print(controllo_neutro(righe, args.viva, args.controllo))
    print()
    print(tabella(righe))
    print()
    print(cambi(righe, args.base))


if __name__ == "__main__":
    main()
