from __future__ import annotations

import argparse
import csv
import gzip
import json
from pathlib import Path
from typing import Any, Iterable, Iterator, TYPE_CHECKING

from analysis.ablazione import fasi, profilo_di, vista_di
from analysis.servizio import ATTACCANTE

if TYPE_CHECKING:
    from ids.engine import IdsEngine

TOLLERANZA_FINE_S = 5.0
ASCOLTO, ESPLORAZIONE, ATTACCO = "ascolto", "esplorazione", "attacco"


def _json(f: Path) -> dict:
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}


def eventi(f: Path) -> Iterator[dict]:
    apri = gzip.open if f.suffix == ".gz" else open
    with apri(f, "rt", encoding="utf-8") as righe:
        for riga in righe:
            if riga.strip():
                yield json.loads(riga)


def vista(radice: Path, nodo: str) -> Path | None:
    for estensione in (".jsonl.gz", ".jsonl"):
        f = radice / "local" / f"{nodo}{estensione}"
        if f.exists():
            return f
    return None


def attivita_attaccante(radice: Path) -> list[tuple[float, float, str]]:
    f = vista(radice, "attacker")
    if f is None:
        return []
    inizio = fine = None
    ascolti: list[tuple[float, float]] = []
    aperture: list[tuple[float, str]] = []
    for ev in eventi(f):
        if ev.get("tipo") != "nodo.attacco":
            continue
        d = ev.get("dati", {})
        if d.get("evento") == "inizio":
            inizio = float(ev["t"])
        elif d.get("evento") == "fine":
            fine = float(ev["t"])
        elif d.get("azione") == "ascolta" and d.get("esito") == "fatto":
            fatto = float(ev["t"])
            durata = float(d.get("speso_s", d.get("secondi", 0.0)))
            ascolti.append((fatto - durata, fatto))
        elif d.get("azione") == "apri":
            aperture.append((float(ev["t"]), str(d.get("sessione", ""))))
    if inizio is None:
        return []
    fine = fine if fine is not None else max([inizio] + [t for t, _ in aperture])
    ascolti = [(max(inizio, a), b) for a, b in ascolti]
    intervalli = [(a, b, ASCOLTO) for a, b in ascolti]
    esplora = [t for t, nome in aperture if nome.startswith("esplora")]
    vere = [t for t, nome in aperture if not nome.startswith("esplora")]
    da = max([inizio] + [b for _, b in ascolti])
    if esplora:
        verso = min([t for t in vere if t >= esplora[0]] or [fine])
        intervalli.append((esplora[0], verso, ESPLORAZIONE))
        da = verso
    elif vere:
        da = min(vere)
    if da < fine:
        intervalli.append((da, fine, ATTACCO))
    return sorted(intervalli)


def etichette_di(t: float, f: dict[str, tuple[float, float]],
                 attivita: list[tuple[float, float, str]]) -> dict[str, Any]:
    fase = next((nome for nome, (a, b) in f.items() if a <= t <= b), "")
    attacco = f.get("attacco")
    dentro = bool(attacco and attacco[0] <= t <= attacco[1])
    cosa = next((nome for a, b, nome in attivita if a <= t <= b), "")
    return {"fase": fase, "in_attacco": int(dentro), "attivita_attaccante": cosa}


def comandi_dopo_finestra(radice: Path, f: dict[str, tuple[float, float]]) -> int | None:
    attacco = f.get("attacco")
    sat = vista(radice, "satellite")
    if attacco is None or sat is None:
        return None
    return sum(1 for ev in eventi(sat)
               if ev.get("tipo") == "app.comando" and ev["dati"].get("peer") == ATTACCANTE
               and float(ev["t"]) > attacco[1] + TOLLERANZA_FINE_S)


def riga_esecuzione(radice: Path, serie: str) -> dict[str, Any]:
    run = _json(radice / "run.json")
    riepilogo = _json(radice / "riepilogo.json")
    attacco = _json(radice / "attacco.json")
    metriche = (_json(radice / "metriche.json").get("esecuzioni") or [{}])[0]
    canale = run.get("canale", {})
    banco = metriche.get("banco") or {}
    osservatore = metriche.get("osservatore") or {}
    f = fasi(radice)
    return {
        "esecuzione": radice.name,
        "serie": serie,
        "scenario": run.get("scenario_id", ""),
        "ramo": attacco.get("ramo", ""),
        "conoscenza": attacco.get("conoscenza", ""),
        "canale": canale.get("nome", ""),
        "ritardo_ms": canale.get("ritardo_ms", ""),
        "jitter_ms": canale.get("jitter_ms", ""),
        "perdita_pct": canale.get("perdita_pct", ""),
        "banda_mbit": canale.get("banda_mbit", ""),
        "canali_per_nodo": json.dumps(run.get("canali_per_nodo") or {}, sort_keys=True),
        "trasporto": (run.get("trasporto") or {}).get("nome", ""),
        "punto_di_cattura": run.get("punto_di_cattura", ""),
        "generazione": (run.get("parametri_ids") or {}).get("generazione", ""),
        "commit": (run.get("codice") or {}).get("commit", ""),
        "modifiche_locali": (run.get("codice") or {}).get("modifiche_locali", ""),
        "chiave_profilo": run.get("chiave_profilo", ""),
        "profilo_riusato": int(bool(run.get("profilo_riusato"))),
        "seme": run.get("seme", ""),
        "semi": json.dumps(run.get("semi") or {}, sort_keys=True),
        "rtt_conforme": riepilogo.get("rtt_conforme", ""),
        "raccolta_completa": riepilogo.get("raccolta_completa", ""),
        "visibilita_caricata": riepilogo.get("visibilita_caricata", ""),
        "cattura_integra": osservatore.get("cattura_integra", ""),
        "pacchetti_persi_osservatore": osservatore.get("pacchetti_persi", ""),
        "in_parallelo": banco.get("in_parallelo", ""),
        "laboratori_accesi_max": banco.get("laboratori_accesi_max", ""),
        "nodo_ids_frenato_s": banco.get("nodo_ids_frenato_s", ""),
        "comandi_attaccante_dopo_la_finestra": comandi_dopo_finestra(radice, f),
        "rilevato": metriche.get("rilevato", ""),
        "latenza_s": metriche.get("latenza_s", ""),
        "falsi_positivi": metriche.get("falsi_positivi", ""),
    }


def _motore(radice: Path, profilo_file: Path) -> tuple[str, IdsEngine]:
    from ids.alarm import AlarmEmitter
    from ids.capture import crea_punto_di_cattura
    from ids.engine import IdsEngine
    from ids.features import FeatureExtractor
    from ids.profile import NormalityProfile

    f, punto = vista_di(radice)
    profilo = NormalityProfile.carica(profilo_file)
    profilo.fissa()
    cattura = crea_punto_di_cattura(punto, f)
    motore = IdsEngine(cattura, profilo, AlarmEmitter([]), estrattore=FeatureExtractor())
    motore.passa_a_rilevazione()
    return cattura, motore


def finestre_di(radice: Path, profili: list[Path], punteggi: bool = True
                ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    from ids.capture import crea_punto_di_cattura
    from ids.features import FeatureExtractor

    f = fasi(radice)
    attivita = attivita_attaccante(radice)
    da = f["nominale"][1] if "nominale" in f and f["nominale"][1] > f["nominale"][0] \
        else f["avvio"][1]
    file_vista, punto = vista_di(radice)
    tutti = list(crea_punto_di_cattura(punto, file_vista).nuovi())
    motore = None
    if punteggi:
        try:
            _, motore = _motore(radice, profilo_di(radice, profili))
        except FileNotFoundError:
            motore = None
    prima, dopo = FeatureExtractor(), FeatureExtractor()
    prima.alimenta(tutti)
    dopo.alimenta([e for e in tutti if e.t >= da])
    globali: list[dict[str, Any]] = []
    per_peer: list[dict[str, Any]] = []
    for fv in [fv for fv in prima.finestre_pronte() if fv.t < da] + dopo.finestre_pronte():
        etichette = etichette_di(fv.t, f, attivita)
        riga: dict[str, Any] = {"esecuzione": radice.name, "t": round(fv.t, 3), **etichette}
        riga.update({k: round(v, 6) for k, v in fv.valori.items()})
        if motore is not None and fv.t >= da:
            d = motore._valuta(fv)
            if d is not None:
                riga["punteggio"] = round(d.punteggio, 4)
                riga["in_allarme"] = int(d.in_allarme)
                riga["appena_alzato"] = int(d.appena_alzato)
                for nome, valore in d.contributi.items():
                    riga[f"contributo_{nome}"] = round(valore, 4)
                riga["segnali_accesi"] = ";".join(sorted(k for k, v in d.segnali.items()
                                                        if v > 0))
        globali.append(riga)
        for peer, valori in fv.per_peer.items():
            per_peer.append({"esecuzione": radice.name, "t": round(fv.t, 3), "peer": peer,
                             "identita": fv.identita_per_peer.get(peer, ""),
                             "attaccante": int(peer == ATTACCANTE), **etichette,
                             **{k: round(v, 6) for k, v in valori.items()}})
    return globali, per_peer


def comandi_di(radice: Path) -> list[dict[str, Any]]:
    f = fasi(radice)
    righe: list[dict[str, Any]] = []
    sat = vista(radice, "satellite")
    if sat is not None:
        for ev in eventi(sat):
            if ev.get("tipo") != "app.comando":
                continue
            d = ev["dati"]
            t = float(ev["t"])
            righe.append({
                "esecuzione": radice.name, "t": round(t, 3), "vista": "satellite",
                "origine": d.get("peer", ""), "identita": d.get("identita", ""),
                "comando": d.get("comando", ""), "servizio": d.get("servizio", ""),
                "sottotipo": d.get("sottotipo", ""), "esito": d.get("esito", ""),
                "fuori_cono": d.get("fuori_cono", ""),
                "attaccante": int(d.get("peer") == ATTACCANTE),
                "fase": etichette_di(t, f, [])["fase"], "latenza_ms": "",
            })
    for stazione in sorted((radice / "local").glob("ground*.jsonl*")):
        for ev in eventi(stazione):
            if ev.get("tipo") != "app.comando":
                continue
            d = ev["dati"]
            t = float(d.get("inviato", ev["t"]))
            righe.append({
                "esecuzione": radice.name, "t": round(t, 3),
                "vista": stazione.name.split(".")[0], "origine": "", "identita": "",
                "comando": d.get("comando", ""), "servizio": "", "sottotipo": "",
                "esito": d.get("esito", ""), "fuori_cono": "", "attaccante": 0,
                "fase": etichette_di(t, f, [])["fase"],
                "latenza_ms": d.get("latenza_ms", "") if d.get("latenza_ms") is not None else "",
            })
    return sorted(righe, key=lambda r: (r["t"], r["vista"]))


def trasferimenti_di(radice: Path) -> list[dict[str, Any]]:
    f = fasi(radice)
    attacco = f.get("attacco")
    run = _json(radice / "run.json")
    canale = run.get("canale", {})
    comuni = {
        "esecuzione": radice.name,
        "scenario": run.get("scenario_id", ""),
        "seme": run.get("seme", ""),
        "trasporto": (run.get("trasporto") or {}).get("nome", ""),
        "perdita_pct": canale.get("perdita_pct", ""),
    }
    righe: list[dict[str, Any]] = []
    for stazione in sorted((radice / "local").glob("ground*.jsonl*")):
        identita = ""
        for ev in eventi(stazione):
            if ev.get("tipo") != "app.sessione":
                continue
            d = ev["dati"]
            if d.get("ruolo") != "telemetria":
                continue
            if d.get("evento") == "apertura":
                identita = str(d.get("identita", "") or "")
                continue
            if d.get("evento") != "chiusura":
                continue
            fine = float(ev["t"])
            durata = float(d.get("durata_s", 0.0) or 0.0)
            inizio = fine - durata
            quote = int(d.get("quote", 0) or 0)
            chiesti = int(d.get("byte_richiesti", 0) or 0)
            ricevuti = int(d.get("byte_ricevuti", 0) or 0)
            durante = bool(attacco and inizio <= attacco[1] and fine >= attacco[0])
            righe.append({
                **comuni,
                "stazione": stazione.name.split(".")[0],
                "identita": identita,
                "inizio": round(inizio, 3), "fine": round(fine, 3),
                "durata_s": round(durata, 3),
                "byte_richiesti": chiesti, "byte_ricevuti": ricevuti,
                "quote": quote,
                "durata_per_quota_s": round(durata / quote, 3) if quote else "",
                "velocita_kb_s": (round(ricevuti / 1024 / durata, 3)
                                  if durata > 0 else ""),
                "incompleto": int(ricevuti < chiesti),
                "fase": etichette_di(inizio, f, [])["fase"],
                "durante_attacco": int(durante),
                "errore": d.get("errore", ""),
            })
    return sorted(righe, key=lambda r: (r["inizio"], r["stazione"]))


def scrivi(righe: list[dict[str, Any]], f: Path, prime: Iterable[str] = ()) -> None:
    prime = list(prime)
    resto: dict[str, None] = {}
    for r in righe:
        resto.update((k, None) for k in r if k not in prime)
    colonne = [c for c in prime if any(c in r for r in righe)] + list(resto)
    apri = gzip.open if f.suffix == ".gz" else open
    f.parent.mkdir(parents=True, exist_ok=True)
    with apri(f, "wt", encoding="utf-8", newline="") as uscita:
        w = csv.DictWriter(uscita, fieldnames=colonne, restval="")
        w.writeheader()
        w.writerows(righe)


PRIME_FINESTRE = ("esecuzione", "t", "fase", "in_attacco", "attivita_attaccante",
                  "punteggio", "in_allarme", "appena_alzato", "segnali_accesi")
PRIME_PEER = ("esecuzione", "t", "peer", "identita", "attaccante", "fase", "in_attacco",
              "attivita_attaccante")
PRIME_COMANDI = ("esecuzione", "t", "vista", "origine", "identita", "attaccante", "comando",
                 "esito", "fase", "latenza_ms")
PRIME_COLONNE_TRASFERIMENTI = ("esecuzione", "scenario", "seme", "trasporto", "perdita_pct",
                  "stazione", "identita", "inizio", "durata_s", "byte_richiesti",
                  "byte_ricevuti", "quote", "durata_per_quota_s", "velocita_kb_s",
                  "incompleto", "durante_attacco", "fase")


def esecuzioni_di(serie: Path) -> list[Path]:
    return [r for r in sorted(serie.iterdir())
            if (r / "etichette.jsonl").exists() and (r / "run.json").exists()]


def esporta(serie: Path, uscita: Path, profili: list[Path], punteggi: bool = True) -> Path:
    destinazione = uscita / serie.name
    esecuzioni, finestre, peer, comandi, trasferimenti = [], [], [], [], []
    for radice in esecuzioni_di(serie):
        print(radice.name)
        esecuzioni.append(riga_esecuzione(radice, serie.name))
        if (radice / "local").exists():
            g, p = finestre_di(radice, [serie] + profili, punteggi)
            finestre += g
            peer += p
        comandi += comandi_di(radice)
        trasferimenti += trasferimenti_di(radice)
    scrivi(esecuzioni, destinazione / "esecuzioni.csv", ("esecuzione", "serie", "scenario"))
    scrivi(finestre, destinazione / "finestre.csv.gz", PRIME_FINESTRE)
    scrivi(peer, destinazione / "finestre_peer.csv.gz", PRIME_PEER)
    scrivi(comandi, destinazione / "comandi.csv.gz", PRIME_COMANDI)
    scrivi(trasferimenti, destinazione / "scarichi.csv.gz", PRIME_COLONNE_TRASFERIMENTI)
    (destinazione / "esportazione.json").write_text(json.dumps(
        {"commit": _commit(), "generazione": _generazione(), "punteggi": punteggi,
         "esecuzioni": len(esecuzioni)}, indent=2), encoding="utf-8")
    return destinazione


def _commit() -> str:
    import subprocess
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def _generazione() -> str:
    from ids.parametri import GENERAZIONE
    return GENERAZIONE


def leggi_configurazione_fissata(f: Path) -> dict[str, Any]:
    c: dict[str, Any] = {"commit": "", "generazione": "", "semi": set()}
    for riga in f.read_text(encoding="utf-8").splitlines():
        riga = riga.split("#", 1)[0].strip()
        if not riga:
            continue
        chiave, _, valore = riga.partition(" ")
        if chiave == "semi":
            c["semi"] |= {int(x) for x in valore.split()}
        elif chiave in ("commit", "generazione"):
            c[chiave] = valore.strip()
    return c


def insieme_di(esecuzione: dict[str, Any], configurazione_fissata: dict[str, Any]) -> str:
    seme = esecuzione.get("seme")
    if seme in ("", None) or int(seme) not in configurazione_fissata["semi"]:
        return "taratura"
    if configurazione_fissata["commit"] and not str(esecuzione.get("commit", "")).startswith(
            configurazione_fissata["commit"]):
        return "taratura"
    if configurazione_fissata["generazione"] and esecuzione.get("generazione") != \
            configurazione_fissata["generazione"]:
        return "taratura"
    return "valutazione"


def scrivi_suddivisione(cartella_dataset: Path, configurazione_fissata: Path) -> Path:
    c = leggi_configurazione_fissata(configurazione_fissata)
    righe = []
    for f in sorted(cartella_dataset.glob("*/esecuzioni.csv")):
        with open(f, encoding="utf-8") as ingresso:
            for r in csv.DictReader(ingresso):
                righe.append({"esecuzione": r["esecuzione"], "serie": r["serie"],
                              "scenario": r["scenario"], "seme": r["seme"],
                              "insieme": insieme_di(r, c)})
    uscita = cartella_dataset / "suddivisione.csv"
    scrivi(righe, uscita, ("esecuzione", "serie", "scenario", "seme", "insieme"))
    return uscita


def main() -> None:
    ap = argparse.ArgumentParser(description="Esportazione del dataset delle serie")
    ap.add_argument("serie", nargs="*", type=Path, help="cartelle delle serie da esportare")
    ap.add_argument("--uscita", type=Path, default=Path("dataset"), help="cartella del dataset")
    ap.add_argument("--profili", nargs="*", type=Path, default=[],
                    help="serie in cui cercare i profili riusati")
    ap.add_argument("--senza-punteggi", dest="punteggi", action="store_false",
                    help="solo grandezze ed etichette, senza rivalutazione")
    ap.add_argument("--suddivisione", type=Path, default=None,
                    help="configurazione fissata; scrive suddivisione.csv")
    args = ap.parse_args()
    for serie in args.serie:
        print(esporta(serie, args.uscita, list(args.serie) + args.profili, args.punteggi))
    if args.suddivisione:
        print(scrivi_suddivisione(args.uscita, args.suddivisione))


if __name__ == "__main__":
    main()
