from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from model.config import CapabilityDescriptor
from ids.features import FeatureVector
from ids.profile import NormalityProfile


CONTROPARTI = {"sessioni_aperte": "sessioni", "comandi_s": "comandi"}

CAPACITA = frozenset({"sessioni"})

COPPIA_NOMINA = False


def riferimento_individuale(st: "Statistica", nome: str) -> float:
    return st.massimo if nome in CAPACITA else st.percentile_alto


def oltre_riferimento(fv: FeatureVector, profilo: NormalityProfile,
                      controparte: str) -> tuple[str, ...]:
    fuori = []
    for peer, voce in fv.per_peer.items():
        valore = voce.get(controparte)
        if valore is None:
            continue
        st = profilo.stat_peer(peer, controparte)
        riferimento = (riferimento_individuale(st, controparte) if st is not None
                       else VolumetricDetector._riferimento_collettivo(
                           profilo, controparte))
        if riferimento is not None and valore > riferimento:
            fuori.append(peer)
    return tuple(sorted(fuori))


def _anche_per_interlocutore(contributi: dict[str, float], fv: FeatureVector,
                             profilo: NormalityProfile) -> None:
    for nome, controparte in CONTROPARTI.items():
        valore = contributi.get(nome)
        if not valore:
            continue
        for peer in oltre_riferimento(fv, profilo, controparte):
            chiave = f"{peer}:{nome}"
            contributi[chiave] = max(contributi.get(chiave, 0.0), valore)


def _con_indirizzo(segnale: str,
                   indirizzi: tuple[str, ...] | None) -> tuple[str, ...]:
    if not indirizzi:
        return (segnale,)
    return tuple(f"{i}:{segnale}" for i in indirizzi)

CUSUM_K = 0.5
CUSUM_H = 12.0
CUSUM_TETTO = CUSUM_H * 1.5
CUSUM_OBLIO = 0.97

DEVIAZIONI_MASSIME_PER_FINESTRA = 3.0


def _satura(x: float, massimo: float) -> float:
    if massimo <= 0:
        return 0.0
    return max(0.0, min(1.0, x / massimo))


@dataclass
class DetectorScore:
    nome: str
    punteggio: float
    attivo: bool = True
    contributi: dict[str, float] = field(default_factory=dict)
    motivo: str = ""

    @property
    def principale(self) -> str:
        if not self.contributi:
            return ""
        return max(self.contributi.items(), key=lambda kv: kv[1])[0]


class Detector(ABC):
    nome = "base"
    richieste: frozenset[str] = frozenset({"rete"})
    sfrutta: frozenset[str] = frozenset()

    def disponibile(self, cap: CapabilityDescriptor) -> bool:
        return cap.soddisfa(self.richieste)

    @abstractmethod
    def valuta(self, fv: FeatureVector, profilo: NormalityProfile) -> DetectorScore:
        ...


class VolumetricDetector(Detector):
    nome = "volumetrico"
    richieste = frozenset({"rete"})
    sfrutta = frozenset({"stato_di_bordo"})

    OSSERVATE = ("pacchetti_s", "byte_s", "nuove_connessioni_s", "sessioni_aperte",
                 "comandi_s", "syn_ritrasmessi_s", "socket_in_apertura")

    RIFERIMENTO_COLLETTIVO = ("sessioni", "comandi")

    SOGLIA_SQUILIBRIO = 3.0

    SCALA_RIFERIMENTO_COLLETTIVO: float | None = None

    def __init__(self, scala_riferimento_collettivo: float | None = None) -> None:
        self._cusum: dict[str, float] = {}
        if scala_riferimento_collettivo is not None:
            self.SCALA_RIFERIMENTO_COLLETTIVO = scala_riferimento_collettivo

    def valuta(self, fv: FeatureVector, profilo: NormalityProfile) -> DetectorScore:
        contributi: dict[str, float] = {}
        for nome in self.OSSERVATE:
            if not fv.ha(nome):
                continue
            st = profilo.stat(nome)
            if st is None:
                continue
            valore = fv.get(nome)
            deviazioni = min(st.deviazioni_oltre_visto(valore), DEVIAZIONI_MASSIME_PER_FINESTRA)
            s = max(0.0, self._cusum.get(nome, 0.0) * CUSUM_OBLIO + deviazioni - CUSUM_K)
            self._cusum[nome] = min(s, CUSUM_TETTO)
            if s > 0:
                contributi[nome] = _satura(s, CUSUM_H)

        squilibrio = self._sessioni_inattive(fv, profilo)
        if squilibrio > 0:
            contributi["sessioni_inattive"] = squilibrio

        contributi.update(self._oltre_riferimento_collettivo(fv, profilo))
        _anche_per_interlocutore(contributi, fv, profilo)

        punteggio = max(contributi.values()) if contributi else 0.0
        principale = max(contributi, key=contributi.get) if contributi else ""
        motivo = ""
        if principale == "sessioni_inattive":
            motivo = "più sessioni aperte del solito, con meno comandi ciascuna"
        elif principale:
            motivo = f"crescita persistente su {principale}"
        return DetectorScore(self.nome, punteggio, True, contributi, motivo=motivo)

    def _oltre_riferimento_collettivo(self, fv: FeatureVector,
                                      profilo: NormalityProfile) -> dict[str, float]:
        if self.SCALA_RIFERIMENTO_COLLETTIVO is None or not profilo.maturo:
            return {}
        fuori: dict[str, float] = {}
        for peer, voce in fv.per_peer.items():
            if not profilo.peer_sconosciuto(peer):
                continue
            for nome in self.RIFERIMENTO_COLLETTIVO:
                valore = voce.get(nome)
                if valore is None:
                    continue
                riferimento = self._riferimento_collettivo(profilo, nome)
                if riferimento is None or valore <= riferimento:
                    continue
                scala = self.SCALA_RIFERIMENTO_COLLETTIVO * max(riferimento, 1.0)
                fuori[f"{peer}:{nome}-oltre-il-riferimento-collettivo"] = _satura(
                    valore - riferimento, scala)
        return fuori

    @staticmethod
    def _riferimento_collettivo(profilo: NormalityProfile,
                                    nome: str) -> float | None:
        alti = [riferimento_individuale(s, nome) for s in
                (profilo.stat_peer(p, nome) for p in profilo.peer_noti)
                if s is not None]
        return max(alti) if alti else None

    def _sessioni_inattive(self, fv: FeatureVector,
                           profilo: NormalityProfile) -> float:
        if not (fv.ha("sessioni_aperte") and fv.ha("comandi_per_sessione")):
            return 0.0
        st_sessioni = profilo.stat("sessioni_aperte")
        st_lavoro = profilo.stat("comandi_per_sessione")
        if st_sessioni is None or st_lavoro is None:
            return 0.0
        deviazioni_sessioni = st_sessioni.deviazioni(fv.get("sessioni_aperte"))
        deviazioni_lavoro = st_lavoro.deviazioni(fv.get("comandi_per_sessione"))
        if deviazioni_sessioni <= self.SOGLIA_SQUILIBRIO or deviazioni_lavoro >= -self.SOGLIA_SQUILIBRIO:
            return 0.0
        return _satura(min(deviazioni_sessioni, -deviazioni_lavoro), 8.0)

    def reimposta(self) -> None:
        self._cusum.clear()


class IdentityCoherenceDetector(Detector):
    nome = "coerenza-identita"
    richieste = frozenset({"rete"})
    sfrutta = frozenset({"applicazione"})

    SOGLIA_DEVIAZIONI = 4.0

    CONFRONTI: tuple[str, ...] = ()

    ETICHETTE = {
        "bbr_gain_medio": "guadagno di ritmo",
        "bbr_cadenza_s": "cadenza del sondaggio",
        "bbr_cadenza_cv": "regolarità del sondaggio",
        "bbr_mrtt": "tempo minimo del modello di BBR",
        "bbr_bw": "banda stimata da BBR",
        "rtt_min_ms": "tempo di andata e ritorno minimo",
    }

    def __init__(self, confronti: tuple[str, ...] | None = None) -> None:
        self.confronti = tuple(self.CONFRONTI if confronti is None else confronti)
        sconosciuti = set(self.confronti) - set(self.ETICHETTE)
        if sconosciuti:
            raise ValueError("confronti sconosciuti: " + ", ".join(sorted(sconosciuti)))

    def valuta(self, fv: FeatureVector, profilo: NormalityProfile) -> DetectorScore:
        contributi: dict[str, float] = {}
        motivi: list[str] = []

        if fv.valori.get("identita_condivise", 0.0) > 0:
            for chiave in _con_indirizzo("identita-condivisa",
                                         fv.attribuzione.get("identita_condivise")):
                contributi[chiave] = 1.0
            motivi.append("stessa identità dichiarata da più origini")
        if fv.valori.get("identita_cambiate", 0.0) > 0:
            for chiave in _con_indirizzo("identita-cambiata",
                                         fv.attribuzione.get("identita_cambiate")):
                contributi[chiave] = 0.7
            motivi.append("identità dichiarata cambiata da un interlocutore")
        if fv.valori.get("identita_fuori_cono", 0.0) > 0:
            for chiave in _con_indirizzo("identita-fuori-cono",
                                         fv.attribuzione.get("identita_fuori_cono")):
                contributi[chiave] = 1.0
            motivi.append("identità dichiarata da una stazione non in visibilità")

        for peer, voce in fv.per_peer.items():
            senza_profilo = False
            dichiarata = fv.identita_per_peer.get(peer)
            attesa = profilo.origine_attesa(dichiarata) if dichiarata else None
            riferimento = peer
            if attesa is not None and attesa != peer:
                contributi[f"{peer}:identita-di-altri"] = 1.0
                motivi.append(f"{peer} dichiara {dichiarata}, identità di {attesa}")
                riferimento = attesa
            elif profilo.peer_sconosciuto(peer) and profilo.maturo:
                contributi[f"{peer}:nuovo"] = 0.35
                motivi.append(f"interlocutore nuovo {peer}")
                senza_profilo = True
            for nome in (() if senza_profilo else self.confronti):
                etichetta = self.ETICHETTE[nome]
                if nome not in voce:
                    continue
                st = profilo.stat_peer(riferimento, nome)
                if st is None:
                    continue
                deviazioni = abs(st.deviazioni_robuste(voce[nome]))
                if deviazioni > self.SOGLIA_DEVIAZIONI:
                    contributi[f"{peer}:{nome}"] = _satura(deviazioni, self.SOGLIA_DEVIAZIONI * 3)
                    motivi.append(f"{etichetta} fuori profilo per {peer}")
            if voce.get("salti_sequenza", 0.0) > 0:
                contributi[f"{peer}:sequenza"] = 1.0
                motivi.append(f"numeri di sequenza ripetuti o arretrati per {peer}")

        for peer, voce in fv.per_peer.items():
            if voce.get("sessioni", 0.0) >= 2 and "rtt_min_ms" in voce:
                st = profilo.stat_peer(peer, "sessioni")
                if st is not None and st.deviazioni_oltre(
                        voce["sessioni"],
                        riferimento_individuale(st, "sessioni")) > 3.0:
                    contributi[f"{peer}:sessioni-doppie"] = 0.6
                    motivi.append(f"sessioni di {peer} oltre il massimo abituale")

        punteggio = max(contributi.values()) if contributi else 0.0
        return DetectorScore(self.nome, punteggio, True, contributi,
                             motivo="; ".join(motivi[:3]))


class DialogueGrammarDetector(Detector):
    nome = "grammatica"
    richieste = frozenset({"applicazione"})
    sfrutta = frozenset()

    MEMORIA = 30.0

    def __init__(self) -> None:
        self._ultimo: dict[str, str] = {}
        self._fuori_catalogo: dict[tuple[str, str], float] = {}

    def valuta(self, fv: FeatureVector, profilo: NormalityProfile) -> DetectorScore:
        contributi: dict[str, float] = {}
        motivi: list[str] = []

        for peer, voce in fv.per_peer.items():
            for chiave, quante in voce.items():
                if not chiave.startswith("cmd_") or quante <= 0:
                    continue
                comando = chiave[4:]
                if profilo.maturo and comando not in profilo.comandi_ammessi:
                    self._fuori_catalogo[(peer, comando)] = fv.t
                prec = self._ultimo.get(peer)
                if prec and profilo.maturo:
                    coppia = f"{prec}>{comando}"
                    if coppia not in profilo.coppie_ammesse:
                        chiave_coppia = f"{peer}:coppia" if COPPIA_NOMINA \
                            else "coppia"
                        contributi[chiave_coppia] = max(
                            contributi.get(chiave_coppia, 0.0), 0.5)
                        motivi.append(f"sequenza mai osservata: {coppia}")
                self._ultimo[peer] = comando

        scaduti = [k for k, t in self._fuori_catalogo.items()
                   if fv.t - t > self.MEMORIA]
        for k in scaduti:
            del self._fuori_catalogo[k]
        for (peer, comando), visto in self._fuori_catalogo.items():
            contributi[f"{peer}:{comando}:fuori-catalogo"] = 1.0
            if fv.t - visto < self.MEMORIA / 2:
                motivi.append(f"comando assente dalla fase nominale: {comando}")

        for nome, peso in (("comandi_s", 1.0), ("dim_media", 0.8), ("dim_massima", 0.8),
                           ("tipi_distinti", 0.6)):
            if not fv.ha(nome):
                continue
            st = profilo.stat(nome)
            if st is None:
                continue
            deviazioni = st.deviazioni(fv.get(nome))
            if deviazioni > 4.0:
                contributi[nome] = _satura(deviazioni, 12.0) * peso
                motivi.append(f"{nome} molto sopra il profilo")

        _anche_per_interlocutore(contributi, fv, profilo)

        punteggio = max(contributi.values()) if contributi else 0.0
        return DetectorScore(self.nome, punteggio, True, contributi,
                             motivo="; ".join(motivi[:3]))


class OnboardDeviationDetector(Detector):
    nome = "deviazione-bordo"
    richieste = frozenset({"stato_di_bordo"})
    sfrutta = frozenset()

    def __init__(self) -> None:
        self._disco_prec: float | None = None
        self._cali_consecutivi = 0

    def valuta(self, fv: FeatureVector, profilo: NormalityProfile) -> DetectorScore:
        contributi: dict[str, float] = {}
        motivi: list[str] = []

        for nome in ("cpu_pct", "memoria_usata_mb", "processi"):
            if not fv.ha(nome):
                continue
            st = profilo.stat(nome)
            if st is None:
                continue
            deviazioni = st.deviazioni(fv.get(nome))
            if deviazioni > 3.5:
                contributi[nome] = _satura(deviazioni, 10.0)
                motivi.append(f"{nome} sopra il profilo")

        if fv.ha("disco_libero_mb"):
            libero = fv.get("disco_libero_mb")
            if self._disco_prec is not None and libero < self._disco_prec - 0.05:
                self._cali_consecutivi += 1
            elif self._disco_prec is not None and libero > self._disco_prec + 0.05:
                self._cali_consecutivi = 0
            self._disco_prec = libero
            if self._cali_consecutivi >= 10:
                contributi["disco_in_calo"] = _satura(self._cali_consecutivi, 40.0)
                motivi.append("spazio su disco in calo costante")

        if fv.get("scritture", 0.0) > 0:
            st = profilo.stat("scritture")
            if st is not None and st.deviazioni_oltre_visto(fv.get("scritture")) > 0.0:
                contributi["scritture"] = 0.7
                motivi.append("scritture su disco oltre il profilo")

        punteggio = max(contributi.values()) if contributi else 0.0
        return DetectorScore(self.nome, punteggio, True, contributi,
                             motivo="; ".join(motivi[:3]))


def rivelatori_predefiniti() -> list[Detector]:
    return [VolumetricDetector(), IdentityCoherenceDetector(),
            DialogueGrammarDetector(), OnboardDeviationDetector()]
