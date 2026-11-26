from __future__ import annotations

import argparse
import csv
import gzip
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator

from common.protocol import TEMPO_MASSIMO_TRASFERIMENTO

DEL_COLLEGAMENTO = ("rtt_medio_ms", "rtt_min_ms", "ritrasmessi_s",
                    "pacchetti_s", "nuove_connessioni_s")

DI_BBR = ("bbr_gain_medio", "bbr_cadenza_s", "bbr_cadenza_cv", "bbr_bw", "bbr_mrtt")

DEI_TRASFERIMENTI = (
    ("trasferimenti", "trasferimenti"),
    ("incompleti", "trasferimenti incompleti"),
    ("velocita_kb_s_mediana", "velocità mediana, kB/s"),
    ("velocita_kb_s_p10", "velocità p10, kB/s"),
    ("velocita_kb_s_p90", "velocità p90, kB/s"),
    ("secondi_per_16mb", "secondi mediani per 16 MB"),
    ("durata_per_quota_mediana_s", "secondi mediani per richiesta"),
    ("durata_per_quota_massima_s", "secondi massimi per richiesta"),
    ("quota_del_tetto_al_massimo", "frazione massima del tetto per richiesta"),
)

CONDIZIONI = ("rtt_conforme", "raccolta_completa", "cattura_integra")


def _vero(valore: Any) -> bool:
    return str(valore).strip().lower() in ("1", "true", "vero", "sì", "si")


def _numero(valore: Any) -> float | None:
    try:
        if valore in ("", None):
            return None
        return float(valore)
    except (TypeError, ValueError):
        return None


def righe(f: Path) -> Iterator[dict[str, str]]:
    if not f.exists():
        return
    apri = gzip.open if f.suffix == ".gz" else open
    with apri(f, "rt", encoding="utf-8", newline="") as ingresso:
        yield from csv.DictReader(ingresso)


def mediana(valori: Iterable[float | None]) -> float | None:
    puliti = [v for v in valori if v is not None]
    return round(statistics.median(puliti), 3) if puliti else None


def percentile(valori: Iterable[float | None], quota: float) -> float | None:
    puliti = sorted(v for v in valori if v is not None)
    if not puliti:
        return None
    k = max(0, min(len(puliti) - 1, int(round(quota * (len(puliti) - 1)))))
    return round(puliti[k], 3)


def affidabile(e: dict[str, str]) -> bool:
    if any(not _vero(e.get(c, "")) for c in CONDIZIONI):
        return False
    if (_numero(e.get("pacchetti_persi_osservatore")) or 0) > 0:
        return False
    if (_numero(e.get("comandi_attaccante_dopo_la_finestra")) or 0) > 0:
        return False
    return True


def fase_di_riferimento(fasi_viste: set[str]) -> str:
    return "nominale" if "nominale" in fasi_viste else "quiete"


def per_esecuzione(cartella: Path) -> dict[str, dict[str, Any]]:
    esecuzioni: dict[str, dict[str, Any]] = {}
    for e in righe(cartella / "esecuzioni.csv"):
        esecuzioni[e["esecuzione"]] = {
            "esecuzione": e["esecuzione"], "serie": e.get("serie", cartella.name),
            "scenario": e.get("scenario", ""), "ramo": e.get("ramo", "") or "-",
            "trasporto": e.get("trasporto", "?"),
            "perdita_pct": _numero(e.get("perdita_pct")),
            "con_attacco": (e.get("ramo", "") or "-") != "-",
            "affidabile": affidabile(e),
            "rilevato": _vero(e.get("rilevato", "")),
            "latenza_s": _numero(e.get("latenza_s")),
        }

    raccolta: dict[str, dict[str, list[float | None]]] = defaultdict(
        lambda: defaultdict(list))
    fasi_viste: dict[str, set[str]] = defaultdict(set)
    estremi: dict[tuple[str, str], list[float]] = defaultdict(list)
    for r in righe(cartella / "finestre.csv.gz"):
        nome, fase = r["esecuzione"], r.get("fase", "")
        if nome not in esecuzioni or not fase:
            continue
        fasi_viste[nome].add(fase)
        t = _numero(r.get("t"))
        if t is not None:
            estremi[(nome, fase)].append(t)
        for colonna in DEL_COLLEGAMENTO:
            raccolta[nome][f"{fase}:{colonna}"].append(_numero(r.get(colonna)))
        medio, minimo = _numero(r.get("rtt_medio_ms")), _numero(r.get("rtt_min_ms"))
        if medio is not None and minimo is not None:
            raccolta[nome][f"{fase}:coda_ms"].append(medio - minimo)

    for r in righe(cartella / "finestre_peer.csv.gz"):
        nome = r["esecuzione"]
        if nome not in esecuzioni or not _vero(r.get("attaccante", "")):
            continue
        if not _vero(r.get("in_attacco", "")):
            continue
        for colonna in ("comandi", "sessioni") + DI_BBR:
            raccolta[nome][f"attaccante:{colonna}"].append(_numero(r.get(colonna)))

    conteggi: dict[tuple[str, str, bool], int] = defaultdict(int)
    latenze: dict[tuple[str, str], list[float | None]] = defaultdict(list)
    for r in righe(cartella / "comandi.csv.gz"):
        nome, fase = r["esecuzione"], r.get("fase", "")
        if nome not in esecuzioni or not fase:
            continue
        attaccante = _vero(r.get("attaccante", ""))
        conteggi[(nome, fase, attaccante)] += 1
        if not attaccante:
            latenze[(nome, fase)].append(_numero(r.get("latenza_ms")))

    for nome, voce in esecuzioni.items():
        riferimento = fase_di_riferimento(fasi_viste.get(nome, set()))
        voce["fase_di_riferimento"] = riferimento
        for fase in (riferimento, "attacco"):
            etichetta = "rif" if fase == riferimento else "att"
            for colonna in DEL_COLLEGAMENTO + ("coda_ms",):
                voce[f"{etichetta}_{colonna}"] = mediana(
                    raccolta[nome].get(f"{fase}:{colonna}", []))
            durata = estremi.get((nome, fase), [])
            secondi = (max(durata) - min(durata)) if len(durata) > 1 else 0.0
            voce[f"{etichetta}_durata_s"] = round(secondi, 1)
            legittimi = conteggi.get((nome, fase, False), 0)
            voce[f"{etichetta}_comandi_legittimi"] = legittimi
            voce[f"{etichetta}_legittimi_s"] = (round(legittimi / secondi, 4)
                                                if secondi > 0 else None)
            voce[f"{etichetta}_latenza_mediana_ms"] = mediana(
                latenze.get((nome, fase), []))
            voce[f"{etichetta}_latenza_p95_ms"] = percentile(
                latenze.get((nome, fase), []), 0.95)
        rif, att = voce.get("rif_legittimi_s"), voce.get("att_legittimi_s")
        voce["servizio_mantenuto"] = (round(att / rif, 4)
                                      if rif and att is not None else None)
        voce["att_comandi_attaccante"] = conteggi.get((nome, "attacco", True), 0)
        secondi = voce.get("att_durata_s") or 0.0
        voce["att_ritmo_attaccante_s"] = (
            round(voce["att_comandi_attaccante"] / secondi, 4) if secondi > 0 else None)
        for colonna in ("comandi", "sessioni") + DI_BBR:
            voce[f"attaccante_{colonna}"] = mediana(
                raccolta[nome].get(f"attaccante:{colonna}", []))
    return esecuzioni


DA_RIASSUMERE = (
    ("rif_rtt_min_ms", "RTT minimo, riferimento"),
    ("att_rtt_min_ms", "RTT minimo, sotto attacco"),
    ("rif_coda_ms", "ritardo di coda, riferimento"),
    ("att_coda_ms", "ritardo di coda, sotto attacco"),
    ("rif_ritrasmessi_s", "ritrasmessi/s, riferimento"),
    ("att_ritrasmessi_s", "ritrasmessi/s, sotto attacco"),
    ("rif_latenza_p95_ms", "latenza p95 dei comandi legittimi, riferimento"),
    ("att_latenza_p95_ms", "latenza p95 dei comandi legittimi, sotto attacco"),
    ("servizio_mantenuto", "servizio mantenuto"),
    ("att_ritmo_attaccante_s", "comandi/s dell'attaccante sul filo"),
    ("attaccante_bbr_gain_medio", "guadagno di ritmo dell'attaccante"),
    ("attaccante_bbr_cadenza_s", "cadenza del sondaggio dell'attaccante"),
)


def righe_trasferimenti(cartella: Path) -> list[dict[str, str]]:
    return list(righe(cartella / "scarichi.csv.gz"))


def riassumi_trasferimenti(elenco: list[dict[str, str]]) -> dict[str, Any]:
    velocita = [_numero(r.get("velocita_kb_s")) for r in elenco]
    per_quota = [_numero(r.get("durata_per_quota_s")) for r in elenco]
    noti = [v for v in per_quota if v is not None]
    mediana_v = mediana(velocita)
    out: dict[str, Any] = {
        "trasferimenti": len(elenco),
        "incompleti": sum(1 for r in elenco if _vero(r.get("incompleto"))),
        "velocita_kb_s_mediana": mediana_v,
        "velocita_kb_s_p10": percentile(velocita, 0.10),
        "velocita_kb_s_p90": percentile(velocita, 0.90),
        "secondi_per_16mb": (round(16 * 1024 / mediana_v, 1)
                             if mediana_v else None),
        "durata_per_quota_mediana_s": mediana(per_quota),
        "durata_per_quota_massima_s": max(noti) if noti else None,
    }
    out["quota_del_tetto_al_massimo"] = (
        round(max(noti) / TEMPO_MASSIMO_TRASFERIMENTO, 3) if noti else None)
    return out


def raggruppa_trasferimenti(elenco: list[dict[str, str]],
                       chiavi: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    gruppi: dict[str, list[dict[str, str]]] = defaultdict(list)
    for r in elenco:
        gruppi[" | ".join(str(r.get(k, "?")) for k in chiavi)].append(r)
    return {nome: riassumi_trasferimenti(voci) for nome, voci in sorted(gruppi.items())}


def tabella_trasferimenti(titolo: str, gruppi: dict[str, dict[str, Any]]) -> str:
    nomi = list(gruppi)
    if not nomi:
        return f"\n{titolo}\n  (nessun trasferimento)\n"
    larghezza = max(len(n) for n in nomi + ["grandezza"]) + 2
    prima = max(len(e) for _, e in DEI_TRASFERIMENTI) + 2
    out = [f"\n{titolo}", "  " + "grandezza".ljust(prima)
           + "".join(n.ljust(larghezza) for n in nomi),
           "  " + "-" * (prima + larghezza * len(nomi))]
    for chiave, etichetta in DEI_TRASFERIMENTI:
        valori = [gruppi[n].get(chiave) for n in nomi]
        if all(v is None for v in valori):
            continue
        out.append("  " + etichetta.ljust(prima)
                   + "".join(("-" if v is None else f"{v:g}").ljust(larghezza)
                             for v in valori))
    return "\n".join(out) + "\n"


def riassumi(elenco: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {"esecuzioni": len(elenco)}
    for chiave, _ in DA_RIASSUMERE:
        out[chiave] = mediana(v.get(chiave) for v in elenco)
    return out


def raggruppa(esecuzioni: list[dict[str, Any]],
              chiavi: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    gruppi: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for v in esecuzioni:
        gruppi[" | ".join(str(v.get(k, "?")) for k in chiavi)].append(v)
    return {nome: riassumi(elenco) for nome, elenco in sorted(gruppi.items())}


def tabella(titolo: str, gruppi: dict[str, dict[str, Any]]) -> str:
    nomi = list(gruppi)
    if not nomi:
        return f"\n{titolo}\n  (nessuna esecuzione)\n"
    larghezza = max(len(n) for n in nomi + ["grandezza"]) + 2
    prima = max(len(e) for _, e in DA_RIASSUMERE) + 2
    out = [f"\n{titolo}", "  " + "grandezza".ljust(prima)
           + "".join(n.ljust(larghezza) for n in nomi),
           "  " + "-" * (prima + larghezza * len(nomi))]
    out.append("  " + "esecuzioni".ljust(prima)
               + "".join(str(gruppi[n]["esecuzioni"]).ljust(larghezza) for n in nomi))
    for chiave, etichetta in DA_RIASSUMERE:
        valori = [gruppi[n].get(chiave) for n in nomi]
        if all(v is None for v in valori):
            continue
        out.append("  " + etichetta.ljust(prima)
                   + "".join(("-" if v is None else f"{v:g}").ljust(larghezza)
                             for v in valori))
    return "\n".join(out) + "\n"


def confronta(cartelle: list[Path], solo_affidabili: bool = True) -> dict[str, Any]:
    tutte: list[dict[str, Any]] = []
    trasferimenti: list[dict[str, str]] = []
    for cartella in cartelle:
        tutte += list(per_esecuzione(cartella).values())
        trasferimenti += righe_trasferimenti(cartella)
    scartate = [v for v in tutte if not v["affidabile"]]
    usate = [v for v in tutte if v["affidabile"]] if solo_affidabili else tutte

    con_attacco = [v for v in usate if v["con_attacco"]]
    senza = [v for v in usate if not v["con_attacco"]]
    perdite = sorted({v["perdita_pct"] for v in usate if v["perdita_pct"] is not None})
    riferimento = perdite[0] if perdite else None
    al_riferimento = [v for v in usate if v["perdita_pct"] == riferimento]

    return {
        "cartelle": [str(c) for c in cartelle],
        "esecuzioni": len(tutte),
        "usate": len(usate),
        "scartate": [{"esecuzione": v["esecuzione"], "scenario": v["scenario"]}
                     for v in scartate],
        "perdite_viste": perdite,
        "perdita_di_riferimento": riferimento,
        "senza_attacco_per_trasporto": raggruppa(senza, ("trasporto",)),
        "al_riferimento_per_trasporto": raggruppa(al_riferimento, ("trasporto",)),
        "per_trasporto_e_perdita": raggruppa(con_attacco, ("trasporto", "perdita_pct")),
        "per_ramo_e_trasporto": raggruppa(con_attacco, ("ramo", "trasporto")),
        "trasferimenti_totali": len(trasferimenti),
        "trasferimenti_quieti_per_trasporto": raggruppa_trasferimenti(
            [r for r in trasferimenti
             if not _vero(r.get("durante_attacco")) and "S0-lunga" in r.get("scenario", "")],
            ("trasporto",)),
        "trasferimenti_per_trasporto_e_perdita": raggruppa_trasferimenti(
            [r for r in trasferimenti if not _vero(r.get("durante_attacco"))],
            ("trasporto", "perdita_pct")),
        "trasferimenti_sotto_attacco": raggruppa_trasferimenti(
            [r for r in trasferimenti if _vero(r.get("durante_attacco"))],
            ("trasporto", "perdita_pct")),
    }


def stampa(esito: dict[str, Any]) -> str:
    parti = [f"dataset: {', '.join(esito['cartelle'])}",
             f"esecuzioni: {esito['esecuzioni']}, usate: {esito['usate']}, "
             f"scartate per condizioni di affidabilità non rispettate: "
             f"{len(esito['scartate'])}"]
    for v in esito["scartate"]:
        parti.append(f"  scartata {v['esecuzione']} ({v['scenario']})")
    parti.append(f"perdite viste: "
                 + ", ".join(f"{p:g}%" for p in esito["perdite_viste"]))
    parti.append(tabella(
        "Senza attacco, per trasporto",
        esito["senza_attacco_per_trasporto"]))
    parti.append(tabella(
        f"Al canale di riferimento ({esito['perdita_di_riferimento']}% di perdita), "
        "per trasporto", esito["al_riferimento_per_trasporto"]))
    parti.append(tabella("Per trasporto e perdita",
                         esito["per_trasporto_e_perdita"]))
    parti.append(tabella("Per ramo e trasporto",
                         esito["per_ramo_e_trasporto"]))
    parti.append(f"trasferimenti: {esito.get('trasferimenti_totali', 0)}")
    parti.append(tabella_trasferimenti(
        "Trasferimenti delle S0-lunga senza attacco, per trasporto",
        esito.get("trasferimenti_quieti_per_trasporto", {})))
    parti.append(tabella_trasferimenti(
        "Trasferimenti fuori dall'attacco, per trasporto e perdita",
        esito.get("trasferimenti_per_trasporto_e_perdita", {})))
    parti.append(tabella_trasferimenti(
        "Trasferimenti durante l'attacco, per trasporto e perdita",
        esito.get("trasferimenti_sotto_attacco", {})))
    return "\n".join(parti)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Confronto fra BBR e congestion control predefinito")
    ap.add_argument("cartelle", nargs="+",
                    help="cartelle dataset/<serie> esportate da analysis.dataset")
    ap.add_argument("--uscita", default=None,
                    help="cartella di confronto-trasporti.json e .txt")
    ap.add_argument("--anche-non-affidabili", action="store_true",
                    help="include le esecuzioni con condizioni di affidabilità non rispettate")
    args = ap.parse_args()

    esito = confronta([Path(c) for c in args.cartelle],
                      solo_affidabili=not args.anche_non_affidabili)
    testo = stampa(esito)
    print(testo)
    if args.uscita:
        fuori = Path(args.uscita)
        fuori.mkdir(parents=True, exist_ok=True)
        (fuori / "confronto-trasporti.json").write_text(
            json.dumps(esito, indent=2, ensure_ascii=False), encoding="utf-8")
        (fuori / "confronto-trasporti.txt").write_text(testo, encoding="utf-8")
        print(f"\nscritto in {fuori}")


if __name__ == "__main__":
    main()
