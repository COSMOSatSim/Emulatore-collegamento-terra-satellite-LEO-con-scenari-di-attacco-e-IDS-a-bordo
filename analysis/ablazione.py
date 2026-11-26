from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, TYPE_CHECKING

from analysis.metrics import origini_attribuite, origini_nominate
from analysis.servizio import ATTACCANTE
from ids.alarm import AlarmEmitter
from ids.capture import CO_RESIDENTE, crea_punto_di_cattura
from ids import detectors
from ids.detectors import (Detector, DetectorScore, IdentityCoherenceDetector,
                           VolumetricDetector, rivelatori_predefiniti)
from ids.engine import IdsEngine
from ids.features import FeatureExtractor
from ids.fusion import ENTITA_GLOBALE, ScoreFusion
from ids.parametri import GENERAZIONE
from ids.profile import NormalityProfile
from model.events import APP_COMANDO

if TYPE_CHECKING:
    from ids.features import FeatureVector

CODA = 300.0

CONFRONTI_TEMPO_MINIMO = ("rtt_min_ms",)
CONFRONTI_BBR = ("rtt_min_ms", "bbr_gain_medio", "bbr_cadenza_s", "bbr_cadenza_cv",
                 "bbr_mrtt", "bbr_bw")


class Voce(StrEnum):
    ESCLUSI = "esclusi"
    CONFRONTI = "confronti"
    SOGLIA = "soglia"
    SOGLIE_RIVELATORE = "soglie_rivelatore"
    SCALA_RIFERIMENTO_COLLETTIVO = "scala_riferimento_collettivo"
    SU = "su"
    COPPIA_NOMINA = "coppia_nomina"
    CAPACITA = "capacita"


@dataclass(frozen=True)
class Configurazione:
    nome: str
    esclusi: tuple[str, ...] = ()
    confronti: tuple[str, ...] | None = None
    soglia: float | None = None
    soglie_rivelatore: dict[str, float] | None = None
    scala_riferimento_collettivo: float | None = None
    su: int | None = None
    coppia_nomina: bool | None = None
    capacita: frozenset[str] | None = None

    @staticmethod
    def da_testo(testo: str) -> "Configurazione":
        nome, _, resto = testo.partition("=")
        esclusi: tuple[str, ...] = ()
        confronti: tuple[str, ...] | None = None
        soglia: float | None = None
        soglie_rivelatore: dict[str, float] | None = None
        scala_riferimento_collettivo: float | None = None
        su: int | None = None
        coppia_nomina: bool | None = None
        capacita: frozenset[str] | None = None
        for parte in filter(None, resto.split(";")):
            chiave, _, valori = parte.partition(":")
            elenco = tuple(v for v in valori.split(",") if v)
            match chiave:
                case Voce.ESCLUSI:
                    esclusi = elenco
                case Voce.CONFRONTI:
                    confronti = elenco
                case Voce.SOGLIA:
                    soglia = float(valori)
                case Voce.SOGLIE_RIVELATORE:
                    soglie_rivelatore = {}
                    for voce in elenco:
                        quale, _, quanto = voce.partition("=")
                        soglie_rivelatore[quale.strip()] = float(quanto)
                case Voce.SCALA_RIFERIMENTO_COLLETTIVO:
                    scala_riferimento_collettivo = float(valori)
                case Voce.SU:
                    su = int(valori)
                case Voce.COPPIA_NOMINA:
                    coppia_nomina = valori.strip() not in ("0", "no", "false", "")
                case Voce.CAPACITA:
                    capacita = frozenset(elenco)
                case _:
                    raise ValueError(f"voce sconosciuta: {chiave}")
        return Configurazione(nome.strip(), esclusi, confronti, soglia,
                              soglie_rivelatore=soglie_rivelatore,
                              scala_riferimento_collettivo=scala_riferimento_collettivo, su=su,
                              coppia_nomina=coppia_nomina, capacita=capacita)


PRESET: dict[str, list[Configurazione]] = {
    "geometria": [
        Configurazione("completa"),
        Configurazione("senza geometria", ("identita-fuori-cono",)),
        Configurazione("senza provenienza", (":identita-di-altri",)),
        Configurazione("senza geometria né provenienza",
                       ("identita-fuori-cono", ":identita-di-altri")),
    ],
    "rivelatori": [
        Configurazione("completa"),
        Configurazione("senza volumetrico", ("volumetrico",)),
        Configurazione("senza coerenza-identita", ("coerenza-identita",)),
        Configurazione("senza grammatica", ("grammatica",)),
        Configurazione("senza deviazione-bordo", ("deviazione-bordo",)),
    ],
    "parametri-decisione": [
        Configurazione("riferimento", coppia_nomina=True, capacita=frozenset()),
        Configurazione("coppia senza indirizzo", coppia_nomina=False,
                       capacita=frozenset()),
        Configurazione("massimo per sessioni", coppia_nomina=True,
                       capacita=frozenset({"sessioni"})),
        Configurazione("entrambi", coppia_nomina=False,
                       capacita=frozenset({"sessioni"})),
    ],
    "trasporti": [
        Configurazione("fissata"),
        Configurazione("tempo minimo", confronti=CONFRONTI_TEMPO_MINIMO),
        Configurazione("BBR", confronti=CONFRONTI_BBR),
    ],
}


class _Escludendo(Detector):
    def __init__(self, interno: Detector, esclusi: tuple[str, ...]) -> None:
        self.interno = interno
        self.esclusi = esclusi
        self.nome = interno.nome
        self.richieste = interno.richieste
        self.sfrutta = interno.sfrutta

    def valuta(self, fv: FeatureVector, profilo: NormalityProfile) -> DetectorScore:
        p = self.interno.valuta(fv, profilo)
        tenuti = {k: v for k, v in p.contributi.items()
                  if not any(k == e or k.endswith(e) for e in self.esclusi)}
        return DetectorScore(p.nome, max(tenuti.values()) if tenuti else 0.0,
                             p.attivo, tenuti, motivo=p.motivo)


def rivelatori_di(c: Configurazione) -> list[Detector]:
    tutti: list[Detector] = []
    for r in rivelatori_predefiniti():
        if r.nome in c.esclusi:
            continue
        if isinstance(r, IdentityCoherenceDetector) and c.confronti is not None:
            r = IdentityCoherenceDetector(confronti=c.confronti)
        if isinstance(r, VolumetricDetector) and c.scala_riferimento_collettivo is not None:
            r = VolumetricDetector(scala_riferimento_collettivo=c.scala_riferimento_collettivo)
        segnali = tuple(e for e in c.esclusi if e not in
                        {"volumetrico", "coerenza-identita", "grammatica", "deviazione-bordo"})
        tutti.append(_Escludendo(r, segnali) if segnali else r)
    return tutti


def _json(f: Path) -> dict:
    return json.loads(f.read_text(encoding="utf-8"))


def fasi(radice: Path) -> dict[str, tuple[float, float]]:
    aperte: dict[str, float] = {}
    out: dict[str, tuple[float, float]] = {}
    for riga in (radice / "etichette.jsonl").read_text(encoding="utf-8").splitlines():
        if not riga.strip():
            continue
        v = json.loads(riga)
        if v.get("etichetta") != "fase":
            continue
        nome = v["dati"]["nome"]
        if v["dati"]["evento"] == "inizio":
            aperte[nome] = float(v["t"])
        elif nome in aperte:
            out[nome] = (aperte.pop(nome), float(v["t"]))
    return out


@dataclass
class SceltaProfilo:
    percorso: Path
    regola: str
    proprietario: str | None = None
    generazione: str | None = None
    scartati: tuple[str, ...] = ()
    radice_proprietario: Path | None = None


def profilo_di(radice: Path, serie: list[Path]) -> Path:
    return scelta_profilo(radice, serie).percorso


def scelta_profilo(radice: Path, serie: list[Path]) -> SceltaProfilo:
    copia = radice / "profilo_riusato.json"
    if copia.exists():
        d = _json(copia)
        proprietario = (d.get("origine") or {}).get("esecuzione")
        return SceltaProfilo(copia, "copia", proprietario,
                             d.get("generazione"),
                             radice_proprietario=_radice_di(proprietario, radice,
                                                            serie))
    if (radice / "profilo.json").exists():
        return SceltaProfilo(radice / "profilo.json", "proprio", radice.name,
                             _json(radice / "profilo.json").get("generazione"),
                             radice_proprietario=radice)
    chiave = _json(radice / "run.json")["chiave_profilo"]
    inizio = float(_json(radice / "orario.json")["inizio"])
    candidati, tardivi = [], []
    cartelle = {radice.parent, *serie}
    for cartella in sorted(cartelle):
        if not cartella.is_dir():
            continue
        for r in sorted(cartella.iterdir()):
            if not ((r / "profilo.json").exists() and (r / "run.json").exists()):
                continue
            if _json(r / "run.json").get("chiave_profilo") != chiave:
                continue
            try:
                fine = estremi_apprendimento(r)[1]
            except (KeyError, OSError, ValueError):
                continue
            (candidati if fine <= inizio else tardivi).append((fine, r))
    if not candidati:
        if tardivi:
            raise FileNotFoundError(
                f"nessun profilo per {chiave} concluso prima di {radice.name}: "
                f"apprendimento in corso in "
                f"{', '.join(r.name for _, r in sorted(tardivi))}")
        raise FileNotFoundError(f"nessun profilo per {chiave}")
    candidati.sort()
    scelto = candidati[-1][1]
    return SceltaProfilo(scelto / "profilo.json", "orario", scelto.name,
                         _json(scelto / "profilo.json").get("generazione"),
                         tuple(r.name for _, r in candidati[:-1]),
                         radice_proprietario=scelto)


def _radice_di(proprietario: str | None, radice: Path,
               serie: list[Path]) -> Path | None:
    if not proprietario:
        return None
    for cartella in {radice.parent, *serie}:
        candidata = cartella / proprietario
        if (candidata / "profilo.json").exists():
            return candidata
    return None


def vista_di(radice: Path) -> tuple[Path, str]:
    for nome, punto in (("idsline", "in-linea"), ("satellite", "co-residente")):
        for estensione in (".jsonl.gz", ".jsonl"):
            f = radice / "local" / f"{nome}{estensione}"
            if f.exists():
                if punto == "co-residente" and (radice / "local" / "idsline.jsonl.gz").exists():
                    continue
                return f, punto
    raise FileNotFoundError(f"nessuna vista del nodo con l'IDS in {radice}")


@dataclass
class Esito:
    esecuzione: str
    configurazione: str
    rilevato: bool | None
    latenza_s: float | None
    falsi_positivi: int
    segnali_apertura: list[str] = field(default_factory=list)
    segnali_in_finestra: list[str] = field(default_factory=list)
    attribuzione_per_entita: str = ""
    latenza_attribuzione_entita_s: float | None = None
    attribuzione: str = ""
    latenza_attribuzione_s: float | None = None
    entita_aperte: list[str] = field(default_factory=list)
    finestre_allarme: int = 0
    finestre_senza_entita: int = 0
    finestre_attaccante_in_allarme: int = 0
    profilo: str = ""
    profilo_regola: str = ""
    profilo_generazione: str | None = None
    profilo_riappreso: bool = False
    profilo_nota: str = ""
    coppia_nomina: bool | None = None
    capacita: list[str] | None = None


def estremi_apprendimento(radice: Path) -> tuple[float, float]:
    orario = _json(radice / "orario.json")
    inizio = float(orario["inizio"])
    f = fasi(radice)
    avvio = f.get("avvio")
    ritardo = (avvio[1] - avvio[0]) if avvio else 0.0
    nominale = f.get("nominale")
    durata = (nominale[1] - nominale[0]) if nominale else 900.0
    return inizio + ritardo, inizio + ritardo + durata


def _impara(radice: Path, eventi: list, chiave: str, fino_a: float,
            quante: int | None = None) -> NormalityProfile:
    profilo = NormalityProfile(chiave=chiave)
    estrattore = FeatureExtractor()
    for ev in eventi:
        if ev.tipo == APP_COMANDO:
            profilo.apprendi_comando(ev.dati.get("peer", "?"),
                                     ev.dati.get("comando", "?"))
    estrattore.alimenta(eventi)
    if eventi:
        profilo.origine["primo_evento_t"] = eventi[0].t
    viste = 0
    for fv in estrattore.finestre_pronte(fino_a):
        if quante is not None and viste >= quante:
            break
        profilo.apprendi(fv)
        profilo.origine["ultima_finestra_t"] = fv.t
        viste += 1
    profilo.fissa()
    return profilo


def _come_confronto(profilo: NormalityProfile) -> dict:
    return {"finestre": profilo.finestre,
            "globale": {k: v.come_dict() for k, v in sorted(profilo.globale.items())},
            "peer": {p: {k: v.come_dict() for k, v in sorted(d.items())}
                     for p, d in sorted(profilo.peer.items())},
            "comandi_ammessi": sorted(profilo.comandi_ammessi),
            "coppie_ammesse": sorted(profilo.coppie_ammesse),
            "peer_noti": sorted(profilo.peer_noti),
            "origine_di_identita": dict(sorted(profilo.origine_di_identita.items()))}


def _come_confronto_salvato(d: dict) -> dict:
    return {"finestre": int(d.get("finestre", 0)),
            "globale": {k: v for k, v in sorted(d.get("globale", {}).items())},
            "peer": {p: {k: v for k, v in sorted(dd.items())}
                     for p, dd in sorted(d.get("peer", {}).items())},
            "comandi_ammessi": sorted(d.get("comandi_ammessi", [])),
            "coppie_ammesse": sorted(d.get("coppie_ammesse", [])),
            "peer_noti": sorted(d.get("peer_noti", [])),
            "origine_di_identita": dict(sorted(d.get("origine_di_identita", {}).items()))}


def quanto_diverge(a: dict, b: dict) -> list[str]:
    fuori = []
    if a["finestre"] != b["finestre"]:
        fuori.append(f"finestre {a['finestre']} contro {b['finestre']}")
    for dove in ("globale", "peer"):
        for nome in sorted(set(a[dove]) | set(b[dove])):
            x, y = a[dove].get(nome), b[dove].get(nome)
            if x is None or y is None:
                fuori.append(f"{dove}/{nome} assente in uno dei profili")
            elif dove == "globale":
                fuori += [f"globale/{nome}.{k}" for k in sorted(set(x) | set(y))
                          if x.get(k) != y.get(k)]
            else:
                for g in sorted(set(x) | set(y)):
                    xx, yy = x.get(g, {}), y.get(g, {})
                    fuori += [f"peer/{nome}/{g}.{k}" for k in sorted(set(xx) | set(yy))
                              if xx.get(k) != yy.get(k)]
    for dove in ("comandi_ammessi", "coppie_ammesse", "peer_noti",
                 "origine_di_identita"):
        if a[dove] != b[dove]:
            fuori.append(dove)
    return fuori


PERIODO_CICLO = 0.5
MASSIMI_AGGANCI = 24

_RIAPPRESI: dict[tuple[str, bool], NormalityProfile] = {}


def riapprendi(radice: Path, c: Configurazione | None = None,
               riproduci: bool = True) -> NormalityProfile:
    memo = (str(radice), riproduci)
    if memo in _RIAPPRESI:
        return _RIAPPRESI[memo]
    vista, punto = vista_di(radice)
    inizio, fine = estremi_apprendimento(radice)
    run = _json(radice / "run.json")
    chiave = str(run.get("chiave_profilo", radice.name))
    tutti = list(crea_punto_di_cattura(punto, vista).nuovi())
    salvato = _json(radice / "profilo.json") if (radice / "profilo.json").exists() else {}
    origine = salvato.get("origine") or {}
    primo, ultima = origine.get("primo_evento_t"), origine.get("ultima_finestra_t")

    quante = int(salvato["finestre"]) if salvato.get("finestre") else None
    if primo is not None and ultima is not None:
        eventi = [e for e in tutti if primo - 1e-9 <= e.t < fine]
        profilo = _impara(radice, eventi, chiave, float(ultima))
        profilo.origine["riprodotto"] = "istanti"
    else:
        profilo = _impara(radice, [e for e in tutti if inizio <= e.t < fine],
                          chiave, fine, quante)
        profilo.origine["riprodotto"] = "no"
        atteso = _come_confronto_salvato(salvato) if salvato else None
        if atteso is not None and not quanto_diverge(_come_confronto(profilo), atteso):
            profilo.origine["riprodotto"] = "taglio"
        elif riproduci and atteso is not None \
                and salvato.get("generazione") == GENERAZIONE:
            visti, candidati = set(), []
            for e in reversed([x for x in tutti
                               if inizio - PERIODO_CICLO * 2 <= x.t < inizio]):
                if e.t not in visti:
                    visti.add(e.t)
                    candidati.append(e)
            for ev in candidati[:MASSIMI_AGGANCI]:
                prova = _impara(radice, [e for e in tutti if ev.t <= e.t < fine],
                                chiave, fine, quante)
                if not quanto_diverge(_come_confronto(prova), atteso):
                    profilo = prova
                    profilo.origine["riprodotto"] = "ricerca"
                    break
    profilo.origine.setdefault("generazione", GENERAZIONE)
    if salvato:
        profilo.origine["atteso_finestre"] = int(salvato.get("finestre", 0))
    _RIAPPRESI[memo] = profilo
    return profilo


def attribuzione_di(decisioni: list, inizio: float,
                    attaccante: str = ATTACCANTE) -> tuple[str, float | None]:
    if not any(d.appena_alzato for d in decisioni):
        return "mancata", None
    legittime = False
    for d in sorted(decisioni, key=lambda d: d.t):
        if not d.in_allarme:
            continue
        origini = origini_attribuite(d.segnali)
        if attaccante in origini:
            return "attribuita", round(d.t - inizio, 3)
        if origini:
            legittime = True
    return ("errata" if legittime else "globale"), None


def attribuzione_per_entita_di(decisioni: list, inizio: float,
                               attaccante: str = ATTACCANTE
                               ) -> tuple[str, float | None]:
    accese = [d for d in sorted(decisioni, key=lambda d: d.t) if d.in_allarme]
    if not any(d.entita_alzate for d in accese):
        return "mancata", None
    legittime = False
    for d in accese:
        for e in sorted(d.entita_alzate):
            if e == attaccante:
                return "attribuita", round(d.t - inizio, 3)
            if e != ENTITA_GLOBALE:
                legittime = True
    return ("errata" if legittime else "globale"), None


def proprietari_di(serie: list[Path]) -> list[Path]:
    return [r for s in serie for r in sorted(s.iterdir())
            if r.is_dir() and (r / "profilo.json").exists()]


def _profilo_per_rivalutazione(profilo_file: Path, strategia: str, conto: dict,
                         radice_proprietario: Path | None = None
                         ) -> tuple[NormalityProfile, dict]:
    generazione = None
    try:
        generazione = _json(profilo_file).get("generazione")
    except (OSError, ValueError):
        pass
    conto["profilo_generazione"] = generazione
    proprietario = radice_proprietario or profilo_file.parent
    da_riapprendere = strategia == "riappreso" or (
        strategia == "automatico" and generazione != GENERAZIONE)
    if da_riapprendere and radice_proprietario is None and not (
            profilo_file.name == "profilo.json"):
        conto["profilo_nota"] = (
            f"non riappreso: {profilo_file.name} è una copia con proprietario "
            f"non trovato; profilo archiviato "
            f"{generazione or 'senza generazione'}, codice {GENERAZIONE}")
        return NormalityProfile.carica(profilo_file), conto
    if da_riapprendere:
        try:
            profilo = riapprendi(proprietario)
            conto["profilo_riappreso"] = True
            conto["profilo_generazione"] = GENERAZIONE
            conto["profilo_nota"] = (
                f"riappreso: profilo archiviato "
                f"{generazione or 'senza generazione'}, codice {GENERAZIONE}")
            return profilo, conto
        except Exception as errore:
            conto["profilo_nota"] = (
                f"non riappreso ({type(errore).__name__}): profilo archiviato "
                f"{generazione or 'senza generazione'}, codice {GENERAZIONE}")
    return NormalityProfile.carica(profilo_file), conto


STRATEGIE_PROFILO = ("automatico", "archiviato", "riappreso")


def rivaluta(radice: Path, profilo_file: Path, c: Configurazione,
            profilo_pronto: NormalityProfile | None = None,
            strategia: str = "automatico",
            radice_proprietario: Path | None = None) -> Esito:
    if strategia not in STRATEGIE_PROFILO:
        raise ValueError(f"strategia del profilo non nota: {strategia}")
    vista, punto = vista_di(radice)
    f = fasi(radice)
    da = f["nominale"][1] if "nominale" in f and f["nominale"][1] > f["nominale"][0] \
        else f["avvio"][1]
    conto = {"profilo": str(profilo_file), "profilo_regola": "pronto" if
             profilo_pronto is not None else strategia}
    if profilo_pronto is not None:
        profilo = profilo_pronto
        conto["profilo_riappreso"] = True
        conto["profilo_generazione"] = GENERAZIONE
    else:
        profilo, conto = _profilo_per_rivalutazione(profilo_file, strategia, conto,
                                              radice_proprietario)
    profilo.fissa()
    cattura = crea_punto_di_cattura(punto, vista)
    opzioni: dict[str, Any] = {}
    if c.soglia is not None:
        opzioni["soglia"] = c.soglia
    if c.soglie_rivelatore is not None:
        opzioni["soglie_rivelatore"] = c.soglie_rivelatore
    if c.su is not None:
        opzioni["su"] = c.su
    fusione = ScoreFusion(**opzioni)
    motore = IdsEngine(cattura, profilo, AlarmEmitter([]), rivelatori=rivelatori_di(c),
                       estrattore=FeatureExtractor(), fusione=fusione)
    motore.passa_a_rilevazione()
    motore.estrattore.alimenta([e for e in cattura.nuovi() if e.t >= da])
    prima = (detectors.COPPIA_NOMINA, detectors.CAPACITA)
    if c.coppia_nomina is not None:
        detectors.COPPIA_NOMINA = c.coppia_nomina
        conto["coppia_nomina"] = c.coppia_nomina
    if c.capacita is not None:
        detectors.CAPACITA = c.capacita
        conto["capacita"] = sorted(c.capacita)
    try:
        for fv in motore.estrattore.finestre_pronte():
            motore.finestre_viste += 1
            motore._valuta(fv)
    finally:
        detectors.COPPIA_NOMINA, detectors.CAPACITA = prima
    attacco = f.get("attacco")
    aperture = [d for d in motore.decisioni if d.appena_alzato]

    def chi(decisioni: list) -> list[str]:
        return sorted({e for d in decisioni for e in d.entita_alzate})

    def nominati(decisioni: list) -> list[str]:
        return sorted({s for d in decisioni if d.in_allarme for s in d.segnali})

    def copertura(decisioni: list) -> dict[str, int]:
        accese = [d for d in decisioni if d.in_allarme]
        return {"finestre_allarme": len(accese),
                "finestre_senza_entita": sum(1 for d in accese
                                             if not d.entita_in_allarme),
                "finestre_attaccante_in_allarme": sum(
                    1 for d in accese if ATTACCANTE in d.entita_in_allarme)}

    if attacco is None or attacco[1] <= attacco[0]:
        return Esito(radice.name, c.nome, None, None, len(aperture),
                     entita_aperte=chi(motore.decisioni),
                     **copertura(motore.decisioni), **conto)
    inizio, fine = attacco
    nella_finestra = [d for d in motore.decisioni
                      if inizio <= d.t <= fine + CODA]
    dentro = [d for d in aperture if inizio <= d.t <= fine + CODA]
    fuori = [d for d in aperture if not (inizio <= d.t <= fine + CODA)]
    categoria, quando = attribuzione_di(nella_finestra, inizio)
    cat_entita, quando_entita = attribuzione_per_entita_di(nella_finestra, inizio)
    if not dentro:
        return Esito(radice.name, c.nome, False, None, len(fuori),
                     entita_aperte=chi(nella_finestra),
                     segnali_in_finestra=nominati(nella_finestra),
                     attribuzione=categoria, latenza_attribuzione_s=quando,
                     attribuzione_per_entita=cat_entita,
                     latenza_attribuzione_entita_s=quando_entita,
                     **copertura(nella_finestra), **conto)
    return Esito(radice.name, c.nome, True, round(dentro[0].t - inizio, 3), len(fuori),
                 sorted(dentro[0].segnali)[:4], entita_aperte=chi(nella_finestra),
                 segnali_in_finestra=nominati(nella_finestra),
                 attribuzione=categoria, latenza_attribuzione_s=quando,
                 attribuzione_per_entita=cat_entita,
                 latenza_attribuzione_entita_s=quando_entita,
                 **copertura(nella_finestra), **conto)


def esecuzioni_di(serie: list[Path]) -> list[Path]:
    return [r for s in serie for r in sorted(s.iterdir())
            if (r / "etichette.jsonl").exists() and (r / "local").exists()]


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Ablazione con rivalutazione fuori linea delle serie")
    ap.add_argument("serie", nargs="+", type=Path, help="cartelle delle serie da rivalutare")
    ap.add_argument("--profili", nargs="*", type=Path, default=[],
                    help="serie dei profili riusati, non rivalutate")
    ap.add_argument("--preset", choices=sorted(PRESET), default=None,
                    help="configurazioni predefinite da rivalutare")
    ap.add_argument("--configurazione", action="append", default=[],
                    help="configurazione nella forma "
                         "nome=esclusi:a,b;confronti:x,y;soglia:0.9; ripetibile")
    ap.add_argument("--su", action="append", type=int, default=[],
                    metavar="N",
                    help="una configurazione per valore dell'isteresi SU, a motore fissato")
    ap.add_argument("--soglia", action="append", type=float, default=[],
                    metavar="VALORE",
                    help="una configurazione per valore della soglia della fusione")
    ap.add_argument("--solo", default=None, help="filtro sul nome delle esecuzioni")
    ap.add_argument("--profilo", choices=STRATEGIE_PROFILO, default="automatico",
                    help="uso del profilo archiviato; automatico riapprende quelli "
                         "di un'altra generazione")
    ap.add_argument("--json", type=Path, default=None, help="file JSON dei risultati")
    args = ap.parse_args()
    configurazioni = list(PRESET.get(args.preset, [])) + [
        Configurazione(f"soglia {v:g}", soglia=v) for v in args.soglia] + [
        Configurazione(f"SU {v}", su=v) for v in args.su] + [
        Configurazione.da_testo(t) for t in args.configurazione]
    if not configurazioni:
        configurazioni = [Configurazione("completa")]
    tutte = list(args.serie) + list(args.profili)
    risultati: list[dict[str, Any]] = []
    saltate: list[tuple[str, str]] = []

    def salva() -> None:
        if args.json:
            args.json.write_text(
                json.dumps(risultati, indent=2, ensure_ascii=False),
                encoding="utf-8")

    for radice in esecuzioni_di(args.serie):
        if args.solo and args.solo not in radice.name:
            continue
        try:
            punto = vista_di(radice)[1]
            if punto != CO_RESIDENTE:
                raise ValueError(f"punto di cattura {punto}: rivalutazione "
                                 f"fuori linea solo per {CO_RESIDENTE}")
            scelta = scelta_profilo(radice, tutte)
        except (FileNotFoundError, ValueError) as errore:
            print(f"{radice.name}: saltata, {errore}", flush=True)
            saltate.append((radice.name, str(errore)))
            continue
        print(f"{radice.name}  profilo {scelta.proprietario or '?'} "
              f"({scelta.regola}, {scelta.generazione or 'senza generazione'})",
              flush=True)
        for c in configurazioni:
            e = rivaluta(radice, scelta.percorso, c, strategia=args.profilo,
                        radice_proprietario=scelta.radice_proprietario)
            voce = e.__dict__ | {"profilo_proprietario": scelta.proprietario,
                                 "profilo_scelta": scelta.regola}
            risultati.append(voce)
            esito = ("senza attacco" if e.rilevato is None else
                     f"rilevato a {e.latenza_s} s" if e.rilevato else "non rilevato")
            print(f"  {c.nome:24s} {esito:22s} fp {e.falsi_positivi}  "
                  f"{e.attribuzione or '-':11s} "
                  f"{e.attribuzione_per_entita or '-':11s} {e.segnali_apertura}")
            if e.profilo_nota:
                print(f"    {e.profilo_nota}")
        salva()
    print()
    if saltate:
        print(f"saltate {len(saltate)} esecuzioni su "
              f"{len(saltate) + len({r['esecuzione'] for r in risultati})}:")
        for nome, perche in saltate:
            print(f"  {nome}  ({perche})")
        print()
    generazioni = {r["profilo_generazione"] for r in risultati}
    if len(generazioni) > 1:
        print(f"profili di generazioni diverse "
              f"({', '.join(str(g) for g in sorted(generazioni, key=str))}): "
              f"esiti non confrontabili (--profilo riappreso per uniformarli)")
    print(f"{'configurazione':24s} {'rilevati':>10s} {'attribuite':>10s} "
          f"{'in allarme':>11s} {'falsi':>6s} {'latenza':>8s}")
    for c in configurazioni:
        suoi = [r for r in risultati if r["configurazione"] == c.nome]
        att = [r for r in suoi if r["rilevato"] is not None]
        presi = [r for r in att if r["rilevato"]]
        lat = sorted(r["latenza_s"] for r in presi if r["latenza_s"] is not None)
        attribuite = sum(1 for r in att if r["attribuzione"] == "attribuita")
        in_allarme = sum(1 for r in att
                         if r.get("attribuzione_per_entita") == "attribuita")
        mediana = f"{lat[len(lat) // 2]:.1f}" if lat else "-"
        print(f"{c.nome:24s} {f'{len(presi)}/{len(att)}':>10s} "
              f"{f'{attribuite}/{len(att)}':>10s} "
              f"{f'{in_allarme}/{len(att)}':>11s} "
              f"{sum(r['falsi_positivi'] for r in suoi):>6d} {mediana:>8s}")
    salva()


if __name__ == "__main__":
    main()
