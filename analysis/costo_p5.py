from __future__ import annotations

import argparse
import json
from pathlib import Path

from analysis.ablazione import (Configurazione, attribuzione_di, esecuzioni_di,
                                fasi, riapprendi, rivelatori_di, scelta_profilo,
                                vista_di)
from ids.capture import crea_punto_di_cattura
from ids.features import FeatureExtractor
from ids.fusion import SOGLIA, ScoreFusion
from ids.parametri import GENERAZIONE
from ids.profile import NormalityProfile

CODA = 300.0

SOGLIE_DA_VALUTARE: tuple[float | None, ...] = (None, 1.00, 0.95, 0.90)

GRANDEZZA = "sessioni_aperte"


def _profilo(radice: Path, serie: list[Path], strategia: str) -> tuple[
        NormalityProfile, dict]:
    scelta = scelta_profilo(radice, serie)
    conto = {"profilo_proprietario": scelta.proprietario,
             "profilo_scelta": scelta.regola,
             "profilo_generazione": scelta.generazione}
    if strategia == "archiviato" or (strategia == "automatico"
                                    and scelta.generazione == GENERAZIONE):
        profilo = NormalityProfile.carica(scelta.percorso)
        conto["profilo_riappreso"] = False
        return profilo, conto
    proprietario = scelta.radice_proprietario
    if proprietario is None:
        raise FileNotFoundError(
            f"proprietario {scelta.proprietario} non trovato: profilo non riappreso")
    profilo = riapprendi(proprietario)
    conto["profilo_riappreso"] = True
    conto["profilo_generazione"] = GENERAZIONE
    conto["profilo_riprodotto"] = profilo.origine.get("riprodotto")
    return profilo, conto


def _perche(profilo: NormalityProfile, livelli: set[float]) -> str:
    st = profilo.stat(GRANDEZZA) if hasattr(profilo, "stat") else None
    st = st or profilo.globale.get(GRANDEZZA)
    if st is None or not livelli:
        return ""
    massimo = st.massimo
    if any(l > massimo for l in livelli):
        return "deriva"
    return "confine" if any(l > st.percentile_alto for l in livelli) else ""


def guarda(radice: Path, serie: list[Path], strategia: str) -> dict:
    profilo, conto = _profilo(radice, serie, strategia)
    profilo.fissa()
    vista, punto = vista_di(radice)
    f = fasi(radice)
    da = f["nominale"][1] if "nominale" in f and f["nominale"][1] > f["nominale"][0] \
        else f["avvio"][1]
    attacco = f.get("attacco")
    con_attacco = attacco is not None and attacco[1] > attacco[0]
    rivelatori = rivelatori_di(Configurazione("completa"))
    estrattore = FeatureExtractor()
    cattura = crea_punto_di_cattura(punto, vista)
    estrattore.alimenta([e for e in cattura.nuovi() if e.t >= da])
    fusioni = {("mai" if t is None else f"{t:.2f}"):
               ScoreFusion(soglie_rivelatore={} if t is None else {"volumetrico": t})
               for t in SOGLIE_DA_VALUTARE}
    decisioni: dict[str, list] = {k: [] for k in fusioni}
    massimo_volumetrico = 0.0
    massima_combinata = 0.0
    livelli: dict[str, set[float]] = {k: set() for k in fusioni}
    finestre = 0
    for fv in estrattore.finestre_pronte():
        finestre += 1
        punteggi = [r.valuta(fv, profilo) for r in rivelatori]
        volumetrico = next((p.punteggio for p in punteggi
                            if p.nome == "volumetrico" and p.attivo), 0.0)
        massimo_volumetrico = max(massimo_volumetrico, volumetrico)
        for nome, fusione in fusioni.items():
            d = fusione.combina(fv.t, punteggi)
            decisioni[nome].append(d)
            massima_combinata = max(massima_combinata, d.punteggio)
            soglia = fusione.soglie_rivelatore.get("volumetrico")
            if soglia is not None and volumetrico >= soglia \
                    and d.punteggio < SOGLIA and GRANDEZZA in fv.valori:
                livelli[nome].add(float(fv.valori[GRANDEZZA]))
    esito = {"nome": radice.name, "serie": radice.parent.name,
             "finestre": finestre, "con_attacco": con_attacco,
             "max_combinata": round(massima_combinata, 4),
             "max_volumetrico": round(massimo_volumetrico, 4),
             "soglie": {}} | conto
    for nome, righe in decisioni.items():
        aperture = [d for d in righe if d.appena_alzato]
        if con_attacco:
            inizio, fine = attacco
            nella = [d for d in righe if inizio <= d.t <= fine + CODA]
            dentro = [d for d in aperture if inizio <= d.t <= fine + CODA]
            fuori = [d for d in aperture if not (inizio <= d.t <= fine + CODA)]
            categoria, quando = attribuzione_di(nella, inizio)
            voce = {"rilevato": bool(dentro),
                    "latenza_s": round(dentro[0].t - inizio, 3) if dentro else None,
                    "fuori": len(fuori), "attribuzione": categoria,
                    "latenza_attribuzione_s": quando}
        else:
            voce = {"rilevato": None, "latenza_s": None, "fuori": len(aperture),
                    "attribuzione": "", "latenza_attribuzione_s": None}
            if aperture:
                voce["perche"] = _perche(profilo, livelli[nome])
                voce["livelli"] = sorted(livelli[nome])
        esito["soglie"][nome] = voce
    return esito


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Costo della soglia P5 del volumetrico sull'archivio")
    ap.add_argument("serie", nargs="+", type=Path, help="cartelle delle serie da rivalutare")
    ap.add_argument("--profilo", default="riappreso",
                    choices=("riappreso", "automatico", "archiviato"),
                    help="strategia del profilo per la rivalutazione")
    ap.add_argument("--solo", default=None,
                    help="filtro sul nome delle esecuzioni")
    ap.add_argument("--jsonl", type=Path, default=None,
                    help="file JSON Lines, un record per esecuzione")
    args = ap.parse_args()
    tutte = [s for s in args.serie if s.is_dir()]
    uscita = open(args.jsonl, "a", encoding="utf-8") if args.jsonl else None
    for radice in esecuzioni_di(tutte):
        if args.solo and args.solo not in radice.name:
            continue
        try:
            esito = guarda(radice, tutte, args.profilo)
        except Exception as errore:
            esito = {"nome": radice.name, "serie": radice.parent.name,
                     "errore": f"{type(errore).__name__}: {errore}"}
        riga = json.dumps(esito, ensure_ascii=False)
        print(riga, flush=True)
        if uscita is not None:
            uscita.write(riga + "\n")
            uscita.flush()
    if uscita is not None:
        uscita.close()


if __name__ == "__main__":
    main()
