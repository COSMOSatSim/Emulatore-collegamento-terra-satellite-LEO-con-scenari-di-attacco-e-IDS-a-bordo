from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from analysis.servizio import ATTACCANTE
from ids.fusion import ENTITA_GLOBALE

CODA_OSSERVAZIONE = 300.0


@dataclass
class Risultato:
    run_id: str
    scenario: str
    punto_di_cattura: str
    rilevato: bool
    latenza_s: float | None
    allarmi_totali: int
    falsi_positivi: int
    allarmi_in_finestra: int
    falsi_positivi_per_ora: float
    durata_nominale_s: float
    rivelatori_attivi: list[str]
    rivelatori_assenti: list[str]
    tempo_in_allarme_s: float = 0.0
    quota_in_allarme: float = 0.0
    servizio: dict[str, Any] = field(default_factory=dict)
    osservatore: dict[str, Any] = field(default_factory=dict)
    costo: dict[str, Any] = field(default_factory=dict)
    gia_in_allarme: bool = False
    trasporto: str = "?"
    generazione: str = "?"
    primo_in_finestra_s: dict[str, float] = field(default_factory=dict)
    primo_segnale_s: dict[str, float] = field(default_factory=dict)
    durata_esposizione_s: float = 0.0
    con_attacco: bool = True
    banco: dict[str, Any] = field(default_factory=dict)
    identificazione: str = ""
    primo_attribuito_s: float | None = None
    identificazione_per_entita: str = ""
    primo_entita_attribuito_s: float | None = None
    primo_invio_s: float | None = None
    latenza_dal_primo_invio_s: float | None = None
    ascolto_s: float | None = None
    entita_in_allarme: list[str] = field(default_factory=list)
    primo_entita_s: float | None = None

    def come_dict(self) -> dict[str, Any]:
        return asdict(self)


def tempo_in_allarme(allarmi: list[dict], fine: float) -> float:
    totale = 0.0
    aperto: float | None = None
    for a in sorted(allarmi, key=lambda x: float(x["t"])):
        t = float(a["t"])
        tipo = a.get("tipo")
        if tipo == "apertura" and aperto is None:
            aperto = t
        elif tipo == "chiusura" and aperto is not None:
            totale += max(0.0, t - aperto)
            aperto = None
    if aperto is not None:
        totale += max(0.0, fine - aperto)
    return round(totale, 3)


def trova(radice: Path, *percorsi: str) -> Path | None:
    for relativo in percorsi:
        f = radice / relativo
        if f.exists():
            return f
    for relativo in percorsi:
        trovati = sorted(radice.rglob(Path(relativo).name))
        if trovati:
            return trovati[0]
    return None


def _righe(percorso: Path) -> list[dict]:
    if not percorso.exists():
        return []
    out = []
    for riga in percorso.read_text(encoding="utf-8", errors="replace").splitlines():
        riga = riga.strip()
        if not riga:
            continue
        try:
            out.append(json.loads(riga))
        except ValueError:
            continue
    return out


def finestra_attacco(etichette: list[dict]) -> tuple[float, float] | None:
    inizio = fine = None
    for v in etichette:
        if v.get("etichetta") != "attacco":
            continue
        if v["dati"].get("evento") == "inizio":
            inizio = float(v["t"]) if inizio is None else min(inizio, float(v["t"]))
        elif v["dati"].get("evento") == "fine":
            fine = float(v["t"]) if fine is None else max(fine, float(v["t"]))
    if inizio is None or fine is None:
        return None
    return (inizio, fine)


def estremi_esecuzione(etichette: list[dict]) -> tuple[float, float]:
    tempi = [float(e["t"]) for e in etichette if "t" in e]
    return (min(tempi), max(tempi)) if tempi else (0.0, 0.0)


def servizio(radice: Path) -> dict[str, Any]:
    f = trova(radice, "analysis/servizio.json", "servizio.json")
    if f is None:
        return {}
    try:
        d = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {k: d[k] for k in ("servizio_mantenuto", "servizio_mantenuto_su_quiete")
            if k in d}


def costo_ids(radice: Path) -> dict[str, Any]:
    f = trova(radice, "local/riepilogo_ids.json")
    if f is None:
        return {}
    try:
        return dict(json.loads(f.read_text(encoding="utf-8")).get("costo") or {})
    except (OSError, ValueError):
        return {}


def riepilogo_osservatore(radice: Path) -> dict[str, Any]:
    candidati = [f for f in (trova(radice, "omniscient/indice.json",
                                   "indice-osservatore.json"),) if f is not None]
    for f in candidati:
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        interfacce = d.get("interfacce")
        if not isinstance(interfacce, dict):
            interfacce = {}
        persi = 0
        completo = d.get("cattura_integra")
        provvisorio = True
        for v in interfacce.values():
            if isinstance(v, dict):
                provvisorio = False
                persi += int(v.get("pacchetti_persi") or 0)
        return {"cattura_integra": completo,
                "pacchetti_persi": None if provvisorio else persi,
                "interfacce": sorted(interfacce),
                "provvisorio": provvisorio}
    return {}


def in_allarme_a(allarmi: list[dict], istante: float) -> bool:
    stato = False
    for a in sorted(allarmi, key=lambda x: float(x["t"])):
        if float(a["t"]) > istante:
            break
        if a.get("tipo") == "apertura":
            stato = True
        elif a.get("tipo") == "chiusura":
            stato = False
    return stato


def primi_segnali(allarmi: list[dict], riferimento: float,
                  non_prima_di: float | None = None) -> dict[str, float]:
    primi: dict[str, float] = {}
    for a in allarmi:
        if a.get("tipo") != "primo-segnale":
            continue
        istante = float(a["t"])
        if non_prima_di is not None and istante < non_prima_di:
            continue
        for nome in a.get("rivelatori_attivi", []):
            t = round(istante - riferimento, 3)
            if nome not in primi or t < primi[nome]:
                primi[nome] = t
    return primi


_ORIGINE = re.compile(r"/(\d{1,3}(?:\.\d{1,3}){3})(?=:|$)")


def origini_nominate(segnali: dict[str, float] | None) -> set[str]:
    trovate: set[str] = set()
    for nome in (segnali or {}):
        trovate.update(_ORIGINE.findall(str(nome)))
    return trovate


SOLO_PRESENZA = ("nuovo",)


def origini_attribuite(segnali: dict[str, float] | None) -> set[str]:
    trovate: set[str] = set()
    for nome in (segnali or {}):
        testo = str(nome)
        if testo.rpartition(":")[2] in SOLO_PRESENZA:
            continue
        trovate.update(_ORIGINE.findall(testo))
    return trovate


def identificazione(allarmi: list[dict], finestra: tuple[float, float] | None,
                    coda: float = CODA_OSSERVAZIONE,
                    attaccante: str = ATTACCANTE) -> tuple[str, float | None]:
    if finestra is None:
        return "", None
    inizio, fine = finestra
    dentro = sorted((a for a in allarmi if inizio <= float(a["t"]) <= fine + coda),
                    key=lambda a: float(a["t"]))
    if not any(a.get("tipo") == "apertura" for a in dentro):
        return "mancata", None
    primo: float | None = None
    legittime = False
    for a in dentro:
        origini = origini_attribuite(a.get("segnali"))
        if attaccante in origini:
            if primo is None:
                primo = round(float(a["t"]) - inizio, 3)
        elif origini:
            legittime = True
    if primo is not None:
        return "attribuita", primo
    return ("errata" if legittime else "globale"), None


def identificazione_per_entita(per_entita: list[dict],
                               finestra: tuple[float, float] | None,
                               coda: float = CODA_OSSERVAZIONE,
                               attaccante: str = ATTACCANTE) -> tuple[str, float | None]:
    if finestra is None:
        return "", None
    inizio, fine = finestra
    dentro = sorted((a for a in per_entita
                     if inizio <= float(a["t"]) <= fine + coda),
                    key=lambda a: float(a["t"]))
    if not dentro:
        return "mancata", None
    primo: float | None = None
    legittime = False
    for a in dentro:
        chi = str(a.get("entita"))
        if chi == attaccante:
            if primo is None:
                primo = round(float(a["t"]) - inizio, 3)
        elif chi != ENTITA_GLOBALE:
            legittime = True
    if primo is not None:
        return "attribuita", primo
    return ("errata" if legittime else "globale"), None


_AZIONI_CHE_TRASMETTONO = ("apri", "comando")


def primo_invio(radice: Path, inizio: float) -> tuple[float | None, float | None]:
    from model.events import leggi_tutto

    vista = trova(radice, "local/attacker.jsonl", "local/attacker.jsonl.gz",
                  "attacker.jsonl", "attacker.jsonl.gz")
    if vista is None:
        return None, None
    invio = ascolto = None
    for ev in leggi_tutto(vista):
        if ev.tipo != "nodo.attacco" or ev.t < inizio:
            continue
        azione = ev.dati.get("azione")
        if azione == "ascolta" and ev.dati.get("esito") == "fatto" and ascolto is None:
            ascolto = round(ev.t - inizio, 3)
        elif azione in _AZIONI_CHE_TRASMETTONO and invio is None:
            invio = round(ev.t - inizio, 3)
    return invio, ascolto


def durata_esposizione(etichette: list[dict], inizio_run: float, fine_run: float,
                       finestra: tuple[float, float] | None,
                       coda: float) -> float:
    nominale_fine = None
    for v in etichette:
        if (v.get("etichetta") == "fase" and v["dati"].get("nome") == "nominale"
                and v["dati"].get("evento") == "fine"):
            nominale_fine = float(v["t"])
    inizio_rilevazione = nominale_fine if nominale_fine is not None else inizio_run
    esposizione = max(0.0, fine_run - inizio_rilevazione)
    if finestra is not None:
        inizio, fine = finestra
        esposizione -= max(0.0, min(fine + coda, fine_run) - max(inizio, inizio_rilevazione))
    return max(0.0, esposizione)


def durata_fase(etichette: list[dict], nome: str) -> float:
    inizio = fine = None
    for v in etichette:
        if v.get("etichetta") == "fase" and v["dati"].get("nome") == nome:
            if v["dati"].get("evento") == "inizio":
                inizio = float(v["t"])
            elif v["dati"].get("evento") == "fine":
                fine = float(v["t"])
    if inizio is None or fine is None:
        return 0.0
    return max(0.0, fine - inizio)


def _senza_morire(funzione: Callable[[Path], dict[str, Any]], radice: Path) -> dict[str, Any]:
    try:
        return funzione(radice)
    except Exception as errore:
        return {"errore": f"{type(errore).__name__}: {errore}"}


def condizioni_del_banco(radice: Path) -> dict[str, Any]:
    f = trova(radice, "config/riepilogo.json")
    if f is None:
        return {}
    try:
        banco = json.loads(f.read_text(encoding="utf-8")).get("banco") or {}
    except (OSError, ValueError):
        return {}
    campioni = banco.get("campioni") or []
    laboratori = [c["laboratori_accesi"] for c in campioni
                  if c.get("laboratori_accesi") is not None]
    carichi = [c["carico_1min"] for c in campioni if c.get("carico_1min") is not None]
    cpu = banco.get("cpu_nodo_ids") or {}
    return {
        "core": banco.get("core"),
        "laboratori_accesi_max": max(laboratori) if laboratori else None,
        "in_parallelo": (max(laboratori) > 1) if laboratori else None,
        "carico_1min_max": max(carichi) if carichi else None,
        "nodo_ids_frenato_s": (round(cpu["throttled_usec"] / 1e6, 3)
                               if "throttled_usec" in cpu else None),
        "nodo_ids_periodi_frenati": cpu.get("nr_throttled"),
    }


def valuta(cartella_run: str | Path,
           coda: float = CODA_OSSERVAZIONE) -> Risultato:
    radice = Path(cartella_run)
    etichette = _righe(trova(radice, "truth/etichette.jsonl") or radice / "_")
    righe_allarmi = _righe(trova(radice, "local/allarmi.jsonl") or radice / "_")
    allarmi = [a for a in righe_allarmi if a.get("entita") is None]
    per_entita = [a for a in righe_allarmi
                  if a.get("entita") is not None and a.get("tipo") == "apertura"]
    conf_file = trova(radice, "config/run.json")
    conf = (json.loads(conf_file.read_text(encoding="utf-8"))
            if conf_file is not None else {})
    generazione = (conf.get("parametri_ids") or {}).get("generazione", "?")
    trasporto = (conf.get("trasporto") or {}).get("nome", "?")

    aperture = [a for a in allarmi if a.get("tipo") == "apertura"]
    finestra = finestra_attacco(etichette)
    nominale = durata_fase(etichette, "nominale")

    inizio_run, fine_run = estremi_esecuzione(etichette)
    durata_run = max(fine_run - inizio_run, 1.0)
    in_allarme = tempo_in_allarme(allarmi, fine_run)

    esposizione = durata_esposizione(etichette, inizio_run, fine_run, finestra, coda)
    ore = max(esposizione, 1.0) / 3600.0

    if finestra is None:
        fp = len(aperture)
        return Risultato(
            run_id=conf.get("run_id", radice.name), scenario=conf.get("scenario_id", "?"),
            punto_di_cattura=conf.get("punto_di_cattura", "?"), rilevato=False,
            latenza_s=None, allarmi_totali=len(aperture), falsi_positivi=fp,
            allarmi_in_finestra=0, falsi_positivi_per_ora=round(fp / ore, 3),
            durata_nominale_s=nominale, durata_esposizione_s=round(esposizione, 1),
            primo_segnale_s=primi_segnali(allarmi, inizio_run),
            generazione=generazione, trasporto=trasporto,
            gia_in_allarme=False, costo=_senza_morire(costo_ids, radice),
            osservatore=_senza_morire(riepilogo_osservatore, radice),
            servizio=_senza_morire(servizio, radice),
            rivelatori_attivi=_rivelatori(aperture, "rivelatori_attivi"),
            rivelatori_assenti=_rivelatori(aperture, "rivelatori_assenti"),
            tempo_in_allarme_s=in_allarme,
            quota_in_allarme=round(in_allarme / durata_run, 3),
            con_attacco=False, banco=condizioni_del_banco(radice),
            entita_in_allarme=sorted({str(a["entita"]) for a in per_entita}))

    inizio, fine = finestra
    dentro = [a for a in aperture if inizio <= float(a["t"]) <= fine + coda]
    fuori = [a for a in aperture if not (inizio <= float(a["t"]) <= fine + coda)]
    latenza = round(float(dentro[0]["t"]) - inizio, 3) if dentro else None
    chi, primo_attribuito = identificazione(allarmi, finestra, coda)
    chi_entita, primo_entita_attribuito = identificazione_per_entita(
        per_entita, finestra, coda)
    invio, ascolto = primo_invio(radice, inizio)
    dal_primo_invio = (round(latenza - invio, 3)
                       if latenza is not None and invio is not None else None)
    return Risultato(
        run_id=conf.get("run_id", radice.name), scenario=conf.get("scenario_id", "?"),
        punto_di_cattura=conf.get("punto_di_cattura", "?"), rilevato=bool(dentro),
        latenza_s=latenza, allarmi_totali=len(aperture), falsi_positivi=len(fuori),
        allarmi_in_finestra=len(dentro),
        falsi_positivi_per_ora=round(len(fuori) / ore, 3), durata_nominale_s=nominale,
        durata_esposizione_s=round(esposizione, 1),
        primo_segnale_s=primi_segnali(allarmi, inizio),
        primo_in_finestra_s=primi_segnali(allarmi, inizio, non_prima_di=inizio),
        generazione=generazione, trasporto=trasporto,
        gia_in_allarme=in_allarme_a(allarmi, inizio),
        costo=_senza_morire(costo_ids, radice),
        osservatore=_senza_morire(riepilogo_osservatore, radice),
        servizio=_senza_morire(servizio, radice),
        rivelatori_attivi=_rivelatori(aperture, "rivelatori_attivi"),
        rivelatori_assenti=_rivelatori(aperture, "rivelatori_assenti"),
        tempo_in_allarme_s=in_allarme,
        quota_in_allarme=round(in_allarme / durata_run, 3),
        banco=condizioni_del_banco(radice),
        identificazione=chi, primo_attribuito_s=primo_attribuito,
        identificazione_per_entita=chi_entita,
        primo_entita_attribuito_s=primo_entita_attribuito,
        primo_invio_s=invio, latenza_dal_primo_invio_s=dal_primo_invio,
        ascolto_s=ascolto,
        entita_in_allarme=sorted({str(a["entita"]) for a in per_entita
                                  if inizio <= float(a["t"]) <= fine + coda}),
        primo_entita_s=next((round(float(a["t"]) - inizio, 3)
                             for a in sorted(per_entita,
                                             key=lambda x: float(x["t"]))
                             if a.get("entita") == ATTACCANTE
                             and inizio <= float(a["t"]) <= fine + coda), None))


def _rivelatori(allarmi: list[dict], campo: str) -> list[str]:
    visti: set[str] = set()
    for a in allarmi:
        visti.update(a.get(campo, []) or [])
    return sorted(visti)


def _massimo(elenco: list[Risultato], campo: str) -> float | None:
    v = [r.costo[campo] for r in elenco if r.costo.get(campo) is not None]
    return round(max(v), 3) if v else None


def _medio(elenco: list[Risultato], campo: str) -> float | None:
    v = [r.costo[campo] for r in elenco if r.costo.get(campo) is not None]
    return round(sum(v) / len(v), 3) if v else None


def confronta(risultati: list[Risultato],
              per: str = "punto_di_cattura",
              anche_generazioni_diverse: bool = False) -> dict[str, Any]:
    generazioni = sorted({r.generazione for r in risultati})
    if len(generazioni) > 1 and not anche_generazioni_diverse:
        return {"confrontato_per": per, "rifiutato": True,
                "ATTENZIONE": ("esecuzioni di generazioni diverse dell'IDS: "
                               + ", ".join(generazioni) + "; confronto non valido "
                               "(--anche-generazioni-diverse per forzare)")}
    per_gruppo: dict[str, list[Risultato]] = {}
    for r in risultati:
        per_gruppo.setdefault(str(getattr(r, per, "?")), []).append(r)
    riassunto: dict[str, Any] = {"confrontato_per": per}
    for punto, elenco in per_gruppo.items():
        attacchi = [r for r in elenco if r.con_attacco]
        rilevati = [r for r in attacchi if r.rilevato]
        latenze = [r.latenza_s for r in rilevati
                   if r.latenza_s is not None and not r.gia_in_allarme]
        dal_invio = [r.latenza_dal_primo_invio_s for r in rilevati
                     if r.latenza_dal_primo_invio_s is not None and not r.gia_in_allarme]
        ore = sum(r.durata_esposizione_s for r in elenco) / 3600.0
        riassunto[punto] = {
            "esecuzioni": len(elenco),
            "esecuzioni_con_attacco": len(attacchi),
            "rilevazioni": len(rilevati),
            "quota_rilevazione": (round(len(rilevati) / len(attacchi), 3)
                                  if attacchi else None),
            "identificazione": dict(Counter(r.identificazione for r in attacchi
                                            if r.identificazione)),
            "quota_attribuita": (round(sum(1 for r in attacchi
                                           if r.identificazione == "attribuita")
                                       / len(attacchi), 3) if attacchi else None),
            "latenza_mediana_s": (round(statistics.median(latenze), 3)
                                  if latenze else None),
            "latenza_dal_primo_invio_mediana_s": (round(statistics.median(dal_invio), 3)
                                                  if dal_invio else None),
            "falsi_positivi": sum(r.falsi_positivi for r in elenco),
            "esposizione_h": round(ore, 3),
            "falsi_positivi_per_ora": (round(sum(r.falsi_positivi for r in elenco) / ore, 3)
                                       if ore > 0 else None),
            "quota_in_allarme_media": round(
                sum(r.quota_in_allarme for r in elenco) / len(elenco), 3) if elenco else 0.0,
            "rss_mb_massimo": _massimo(elenco, "rss_mb_massimo"),
            "cpu_pct_medio": _medio(elenco, "cpu_pct_medio"),
        }
    altre = {"punto_di_cattura", "trasporto"} - {per}
    for dimensione in sorted(altre):
        valori = sorted({str(getattr(r, dimensione, "?")) for r in risultati})
        if len(valori) > 1:
            riassunto[f"attenzione_{dimensione}"] = (
                f"esecuzioni diverse anche per {dimensione}: "
                + ", ".join(valori) + "; più di un elemento variato")
    if len(generazioni) > 1:
        riassunto["ATTENZIONE"] = (
            "esecuzioni di generazioni diverse dell'IDS: "
            + ", ".join(generazioni) + "; confronto non valido")
    else:
        riassunto["generazione"] = generazioni[0] if generazioni else "?"
    return riassunto


confronta_dispiegamenti = confronta


def main() -> None:
    ap = argparse.ArgumentParser(description="Metriche di una o più esecuzioni")
    ap.add_argument("cartelle", nargs="+", help="cartelle delle esecuzioni")
    ap.add_argument("--confronta", action="store_true",
                    help="confronto fra gruppi, per punto di cattura salvo --confronta-per")
    ap.add_argument("--confronta-per", default=None,
                    choices=("punto_di_cattura", "trasporto"),
                    help="dimensione del confronto; implica --confronta")
    ap.add_argument("--anche-generazioni-diverse", action="store_true",
                    help="confronta anche esecuzioni di generazioni diverse, con avviso")
    args = ap.parse_args()

    risultati = [valuta(c) for c in args.cartelle]
    uscita: dict[str, Any] = {"esecuzioni": [r.come_dict() for r in risultati]}
    if args.confronta or args.confronta_per:
        uscita["confronto"] = confronta(
            risultati, args.confronta_per or "punto_di_cattura",
            anche_generazioni_diverse=args.anche_generazioni_diverse)
    print(json.dumps(uscita, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
