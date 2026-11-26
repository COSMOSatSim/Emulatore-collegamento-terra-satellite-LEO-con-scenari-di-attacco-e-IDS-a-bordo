from __future__ import annotations

import argparse
import json
import os
import random
import signal
import socket
import statistics
import struct
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Iterator

from common.protocol import (AREA_DI_VERIFICA_BYTE, CATALOGO,
                             IDENTIFICATORI_NOTI, Riassemblatore,
                             SERVIZIO_FUNZIONE, codifica_grezzo,
                             codifica_comando, decodifica_comando,
                             richiesta_di_verifica)
from common.transport import crea_socket_client
from model.config import BBR
from model.events import EventLog
from sensor.wiretap import analizza_telaio, cattura_promiscua


class _Trovato(Exception):
    pass


PORTA_PREDEFINITA = 5000
NODO_ATTACCO = "nodo.attacco"

SOTTOTIPO_INESISTENTE = 127

PACCHETTI_DA_CATTURARE = 30


class TipoAzione(StrEnum):
    APRI = "apri"
    COMANDO = "comando"
    RIMANDA = "rimanda"
    CHIUDI = "chiudi"
    ASCOLTA = "ascolta"
    ATTENDI = "attendi"


@dataclass(frozen=True)
class Azione:
    tipo: str
    sessione: str = ""
    comando: str = ""
    byte: int = 0
    secondi: float = 0.0
    identita: str = ""
    sequenza: int | None = None
    obiettivo: str = ""
    grezzo: bytes = b""
    ripetizioni: int = 1
    nota: str = ""


def apri(sessione: str, identita: str = "", nota: str = "") -> Azione:
    return Azione(TipoAzione.APRI, sessione=sessione, identita=identita, nota=nota)


def comando(sessione: str, nome: str, byte: int = 0, sequenza: int | None = None,
            identita: str = "", ripetizioni: int = 1, nota: str = "") -> Azione:
    return Azione(TipoAzione.COMANDO, sessione=sessione, comando=nome, byte=byte,
                  sequenza=sequenza, identita=identita,
                  ripetizioni=max(1, ripetizioni), nota=nota)


def rimanda(sessione: str, grezzo: bytes, nota: str = "") -> Azione:
    return Azione(TipoAzione.RIMANDA, sessione=sessione, grezzo=grezzo,
                  byte=len(grezzo), nota=nota)


def attendi(secondi: float, nota: str = "") -> Azione:
    return Azione(TipoAzione.ATTENDI, secondi=secondi, nota=nota)


def chiudi(sessione: str, nota: str = "") -> Azione:
    return Azione(TipoAzione.CHIUDI, sessione=sessione, nota=nota)


def ascolta(secondi: float, obiettivo: str = "", nota: str = "") -> Azione:
    return Azione(TipoAzione.ASCOLTA, secondi=secondi, obiettivo=obiettivo, nota=nota)


@dataclass(frozen=True)
class Strategie:
    identita_dichiarata: str = "nessuna"
    identita_esplorazione: str = "segnaposto"
    imita: str = "aggregata"
    dimensione_comandi: str = "fissa-16"
    vittima: str = "prima-alfabetica"
    jitter: str = "no"
    forma_sessioni: str = "continua"
    durata_sessione_s: float = 150.0
    pausa_sessione_s: float = 25.0
    variabilita_sessione: float = 0.4
    distanza_raffiche_s: float = 1.5
    variabilita: float = 0.25


@dataclass
class Ricognizione:
    comandi_noti: tuple[str, ...] = ()
    identita_osservata: str = ""
    cadenza_osservata_s: float = 0.0
    dimensione_tipica: int = 0
    sequenza_osservata: int | None = None
    pacchetti_catturati: tuple[bytes, ...] = ()
    ascolto_speso_s: float | None = None

    @property
    def completa(self) -> bool:
        return bool(self.comandi_noti)

    DIMENSIONE_DI_RIPIEGO = 16

    @classmethod
    def informata(cls, identita: str = "ground1",
                  comandi_al_minuto: float = 12.0,
                  dimensione: int | None = None) -> "Ricognizione":
        return cls(comandi_noti=tuple(CATALOGO),
                   identita_osservata=identita,
                   cadenza_osservata_s=60.0 / max(comandi_al_minuto, 1e-9),
                   dimensione_tipica=(cls.DIMENSIONE_DI_RIPIEGO
                                      if dimensione is None else int(dimensione)))


class SequenzaAttacco(ABC):
    ramo: str = "-"
    nome: str = "sequenza d'attacco"
    firma: tuple[str, ...] = ()
    forma_fissa: bool = False
    richiede_esplorazione: bool = False
    TETTO_ASCOLTO = 90.0

    IDENTITA_FITTIZIA = "ground5"
    IDENTITA_DI_SONDAGGIO = "ground6"

    def __init__(self, durata: float, seme: int | None = None,
                 pazienza: float = 1.0, ritmo_nominale_s: float | None = None,
                 strategie: Strategie | None = None) -> None:
        self.strategie = strategie or Strategie()
        self.durata = durata
        self.pazienza = max(1.0, pazienza)
        self.caso = random.Random(seme)
        self.ritmo_nominale_s = ritmo_nominale_s

    @property
    def ritmo_massimo(self) -> float | None:
        if self.ritmo_nominale_s is None or self.pazienza <= 1.0:
            return None
        return self.ritmo_nominale_s * self.pazienza

    def _durata_di_sessione(self) -> float:
        base = self.strategie.durata_sessione_s
        return max(5.0, self.caso.gauss(
            base, base * self.strategie.variabilita_sessione))

    def _pausa_di_sessione(self) -> float:
        base = self.strategie.pausa_sessione_s
        return max(0.5, self.caso.gauss(
            base, base * self.strategie.variabilita_sessione))

    def identita_da_dichiarare(self, ric: Ricognizione) -> str:
        strategia = self.strategie.identita_dichiarata
        if strategia == "rubata":
            return ric.identita_osservata or self.IDENTITA_FITTIZIA
        if strategia == "fittizia":
            return self.IDENTITA_FITTIZIA
        return ""

    def identita_esplorativa(self) -> str:
        if self.strategie.identita_esplorazione == "fittizia":
            return self.IDENTITA_DI_SONDAGGIO
        return "?"

    def esplorazione(self, ric: Ricognizione) -> Iterator[Azione]:
        if ric.completa:
            return
        yield ascolta(self.TETTO_ASCOLTO, obiettivo="identita",
                      nota="ascolto passivo fino a un'identità")
        yield apri("esplora", identita=self.identita_esplorativa(),
                   nota="sessione di sondaggio")
        for nome in ("test", "housekeeping", "funzione", "memoria", "software"):
            yield comando("esplora", nome, byte=8, nota="sondaggio del catalogo")
            yield attendi(1.5)
        yield comando("esplora", "sconosciuto", byte=8,
                      nota="comando fuori catalogo, limite del catalogo")
        yield attendi(1.5)
        yield chiudi("esplora")

    @abstractmethod
    def attacco(self, ric: Ricognizione, durata: float) -> Iterator[Azione]:
        pass

    def azioni(self, ric: Ricognizione) -> Iterator[Azione]:
        passi = list(self.esplorazione(ric))
        attese = sum(a.secondi for a in passi if a.tipo != TipoAzione.ASCOLTA)
        tetto = sum(a.secondi for a in passi if a.tipo == TipoAzione.ASCOLTA)
        yield from passi
        speso = attese + (tetto if ric.ascolto_speso_s is None
                          else ric.ascolto_speso_s)
        restante = max(0.0, self.durata - speso)
        tetto = self.ritmo_massimo
        intervallo_minimo = 1.0 / tetto if tetto else 0.0
        accumulato = speso_totale = 0.0
        aperte: dict[str, str] = {}
        aperta_da: dict[str, float] = {}
        a_raffiche = (self.strategie.forma_sessioni == "a-raffiche"
                      and not self.forma_fissa)
        for azione in self.attacco(ric, restante / self.pazienza):
            if azione.tipo == TipoAzione.ATTENDI and azione.secondi:
                secondi = azione.secondi * self.pazienza
                if self.strategie.jitter == "come-il-carico":
                    secondi = max(0.05, self.caso.gauss(
                        secondi, secondi * self.strategie.variabilita))
                azione = replace(azione, secondi=secondi)
                accumulato += azione.secondi
                speso_totale += azione.secondi
                yield azione
                continue
            if azione.tipo == TipoAzione.COMANDO and intervallo_minimo:
                mancante = intervallo_minimo - accumulato
                if mancante > 0:
                    if speso_totale + mancante > restante:
                        return
                    yield Azione(tipo=TipoAzione.ATTENDI, secondi=mancante)
                    speso_totale += mancante
                accumulato = 0.0
            if azione.tipo == TipoAzione.APRI:
                aperte[azione.sessione] = azione.identita
                aperta_da[azione.sessione] = speso_totale
            elif azione.tipo == TipoAzione.CHIUDI:
                aperte.pop(azione.sessione, None)
                aperta_da.pop(azione.sessione, None)
            yield azione
            if a_raffiche and azione.sessione in aperte:
                nome = azione.sessione
                if speso_totale - aperta_da.get(nome, 0.0) >= self._durata_di_sessione():
                    identita = aperte[nome]
                    yield chiudi(nome, nota="chiusura della raffica")
                    pausa = self._pausa_di_sessione()
                    if speso_totale + pausa > restante:
                        return
                    yield Azione(tipo=TipoAzione.ATTENDI, secondi=pausa)
                    speso_totale += pausa
                    yield apri(nome, identita=identita, nota="riapertura della raffica")
                    aperta_da[nome] = speso_totale


class EsaurimentoSessioni(SequenzaAttacco):
    forma_fissa = True
    ramo = "sessioni"
    nome = "esaurimento delle sessioni"
    firma = ("nuove_connessioni_s molto sopra il profilo",
             "sessioni_aperte in crescita",
             "handshake_falliti_s invariato, il servizio non ha tetto di sessioni",
             "allarme da sessioni_aperte, memoria_usata_mb e interlocutore nuovo")

    SESSIONI = 200
    AL_SECONDO = 12.0

    def attacco(self, ric: Ricognizione, durata: float) -> Iterator[Azione]:
        pausa = 1.0 / self.AL_SECONDO
        aperte: list[str] = []
        for i in range(self.SESSIONI):
            nome = f"flood{i:03d}"
            yield apri(nome, identita=self.identita_da_dichiarare(ric))
            aperte.append(nome)
            yield attendi(pausa)
        yield attendi(max(0.0, durata - self.SESSIONI * pausa - 5.0),
                      nota="sessioni trattenute fino a fine finestra")
        for nome in aperte:
            yield chiudi(nome)


class SaturazioneComandi(SequenzaAttacco):
    ramo = "comandi"
    nome = "saturazione dei comandi"
    firma = ("comandi_s e pacchetti_s sopra il profilo",
             "rtt_medio_ms e coda_ms in crescita prima del calo del ritmo",
             "grammatica su comandi_s e tipi_distinti molto sopra il profilo",
             "cpu_pct del container del satellite in crescita")

    SESSIONI = 4
    AL_SECONDO = 60.0

    def attacco(self, ric: Ricognizione, durata: float) -> Iterator[Azione]:
        sessioni = [f"carico{i}" for i in range(self.SESSIONI)]
        for nome in sessioni:
            yield apri(nome, identita=self.identita_da_dichiarare(ric))
        pausa = 1.0 / self.AL_SECONDO
        fatte = 0.0
        scelta = [n for n in ("test", "housekeeping", "funzione")
                  if not ric.completa or n in ric.comandi_noti] or ["test"]
        while fatte < durata - 5.0:
            for nome in sessioni:
                yield comando(nome, self.caso.choice(scelta),
                              byte=ric.dimensione_tipica or 16)
            yield attendi(pausa)
            fatte += pausa
        for nome in sessioni:
            yield chiudi(nome)


class EsaurimentoMemoria(SequenzaAttacco):
    ramo = "memoria"
    nome = "esaurimento della memoria di bordo"
    firma = ("disco_libero_mb in calo costante: disco_in_calo da 10 cali consecutivi",
             "scritture su disco oltre il profilo, senza indirizzo del peer",
             "dim_media e dim_massima sopra il profilo dal primo blocco",
             "volumetrico attivo: comandi_s del peer sopra il profilo")

    BLOCCO = 60_000
    AL_SECONDO = 4.0

    def attacco(self, ric: Ricognizione, durata: float) -> Iterator[Azione]:
        yield apri("memoria", identita=self.identita_da_dichiarare(ric))
        pausa = 1.0 / self.AL_SECONDO
        trascorso = 0.0
        while trascorso < durata - 5.0:
            yield comando("memoria", "memoria", byte=self.BLOCCO,
                          nota="scrittura di bordo")
            yield attendi(pausa)
            trascorso += pausa
        yield chiudi("memoria")


class SessioniTrattenute(SequenzaAttacco):
    forma_fissa = True
    ramo = "sessioni-lente"
    nome = "sessioni aperte e trattenute"
    firma = ("sessioni_aperte sopra il profilo, in crescita lenta",
             "comandi_per_sessione in calo, segnale di squilibrio mai attivo",
             "nuove_connessioni_s entro il profilo",
             "durata_media_s e durata_max_s in crescita, non osservate dai rivelatori",
             "allarme da sessioni_aperte, memoria_usata_mb e interlocutore nuovo insieme")

    SESSIONI = 30
    INTERVALLO_APERTURA = 10.0
    KEEPALIVE = 45.0

    def attacco(self, ric: Ricognizione, durata: float) -> Iterator[Azione]:
        aperte: list[str] = []
        trascorso = 0.0
        for i in range(self.SESSIONI):
            nome = f"lenta{i:02d}"
            yield apri(nome, identita=self.identita_da_dichiarare(ric))
            aperte.append(nome)
            yield attendi(self.INTERVALLO_APERTURA)
            trascorso += self.INTERVALLO_APERTURA
            if trascorso > durata - self.KEEPALIVE:
                break
        while trascorso + self.KEEPALIVE < durata - 5.0:
            yield comando(self.caso.choice(aperte), "test", byte=4,
                          nota="mantenimento della sessione")
            yield attendi(self.KEEPALIVE)
            trascorso += self.KEEPALIVE
        for nome in aperte:
            yield chiudi(nome)


class InondazioneDelCanale(SequenzaAttacco):
    forma_fissa = True
    ramo = "inondazione"
    nome = "inondazione del canale"
    firma = ("comandi_s, dim_media e sessioni_aperte molto sopra il profilo",
             "rtt_medio_ms in lieve crescita, ritrasmessi_s del satellite invariato",
             "comandi legittimi consegnati, servizio_mantenuto vicino a 1",
             "rilevazione immediata attesa")

    SESSIONI = 8
    BLOCCO = 60_000
    RIPETIZIONI = 50
    PASSO = 0.25
    PASSI_FRA_RICAMBI = 20

    def attacco(self, ric: Ricognizione, durata: float) -> Iterator[Azione]:
        sessioni = [f"piena{i}" for i in range(self.SESSIONI)]
        for nome in sessioni:
            yield apri(nome, identita=self.identita_da_dichiarare(ric))
        trascorso = 0.0
        giro = 0
        while trascorso < durata - 5.0:
            giro += 1
            for nome in sessioni:
                yield comando(nome, "test", byte=self.BLOCCO,
                              ripetizioni=self.RIPETIZIONI,
                              nota="scrittura di riempimento del canale")
            if giro % self.PASSI_FRA_RICAMBI == 0:
                effimera = f"ricambio{giro}"
                yield apri(effimera, identita=self.identita_da_dichiarare(ric))
                yield chiudi(effimera)
            yield attendi(self.PASSO)
            trascorso += self.PASSO
        for nome in sessioni:
            yield chiudi(nome)


class FalsificazioneIdentita(SequenzaAttacco):
    ramo = "identita-presa-in-prestito"
    nome = "falsificazione dell'identità"
    firma = ("identità presa in prestito dall'apertura: identita-di-altri se appresa nel profilo",
             "identita-condivisa con la stazione attiva, identita-fuori-cono fuori visibilità",
             "salti_sequenza sui comandi ripetuti nella seconda metà")

    OGNI_QUANTE_SI_RIPRESENTA = 8

    def attacco(self, ric: Ricognizione, durata: float) -> Iterator[Azione]:
        presa = ric.identita_osservata or "ground1"
        yield apri("gemella", identita=presa,
                   nota=f"identità dichiarata {presa}, di un'altra stazione")
        cadenza = ric.cadenza_osservata_s or 5.0
        trascorso = 0.0
        giro = 0
        while trascorso < (durata - 10.0) / 2:
            giro += 1
            if giro % self.OGNI_QUANTE_SI_RIPRESENTA == 0:
                yield comando("gemella", "identita", identita=presa)
            else:
                yield comando("gemella", "housekeeping",
                              byte=ric.dimensione_tipica or 16)
            yield attendi(cadenza)
            trascorso += cadenza
        base = ric.sequenza_osservata if ric.sequenza_osservata is not None else 1
        while trascorso < durata - 5.0:
            yield comando("gemella", "funzione", byte=ric.dimensione_tipica or 16,
                          sequenza=base, nota="ripetizione del numero di sequenza")
            yield attendi(cadenza)
            trascorso += cadenza
        yield chiudi("gemella")


class ReplayComandi(SequenzaAttacco):
    ramo = "replay-telecomandi"
    nome = "replay dei comandi"
    richiede_esplorazione = True
    firma = ("salti_sequenza dell'origine: numeri già osservati",
             "nessuna identità dichiarata",
             "nessun comando fuori catalogo",
             "dimensioni entro il profilo, comandi_s a tratti oltre per il ritmo aggregato",
             "ricognizione senza traffico verso il satellite")

    PACCHETTI = PACCHETTI_DA_CATTURARE

    def esplorazione(self, ric: Ricognizione) -> Iterator[Azione]:
        if ric.pacchetti_catturati:
            return
        yield ascolta(self.TETTO_ASCOLTO, obiettivo="pacchetti",
                      nota="ascolto passivo dei comandi da ripetere")

    def attacco(self, ric: Ricognizione, durata: float) -> Iterator[Azione]:
        catturati = ric.pacchetti_catturati
        if not catturati:
            return
        yield apri("eco", identita=self.identita_da_dichiarare(ric))
        cadenza = ric.cadenza_osservata_s or 5.0
        trascorso = 0.0
        giro = 0
        while trascorso < durata - 5.0:
            pacchetto = catturati[giro % len(catturati)]
            giro += 1
            yield rimanda("eco", pacchetto,
                          nota=f"comando ripetuto, giro {giro}")
            yield attendi(cadenza)
            trascorso += cadenza
        yield chiudi("eco")


class VerificaEModifica(SequenzaAttacco):
    ramo = "verifica-e-modifica"
    nome = "verifica e modifica della memoria di bordo"
    firma = ("comando di verifica assente dalla fase nominale",
             "dim_media e dim_massima sopra il profilo solo alla scrittura da 512 byte",
             "una sola scrittura del ramo, da 512 byte: disco_libero_mb invariato",
             "grammatica supera da sola la soglia con il fuori-catalogo di verifica")

    VERIFICHE_MINIME = 4
    PAUSA = 8.0
    MODIFICA_BYTE = 512
    CODA = 30.0

    def attacco(self, ric: Ricognizione, durata: float) -> Iterator[Azione]:
        yield apri("sonda", identita=self.identita_da_dichiarare(ric))
        cadenza = ric.cadenza_osservata_s or 5.0
        preludio = 3 * cadenza
        for _ in range(3):
            yield comando("sonda", "test", byte=8)
            yield attendi(cadenza)
        disponibile = max(0.0, durata - preludio - self.CODA)
        quante = max(self.VERIFICHE_MINIME, int(disponibile / self.PAUSA))
        trascorso = 0.0
        for i in range(quante):
            yield comando("sonda", "verifica",
                          nota=f"verifica {i + 1} di {quante}")
            yield attendi(self.PAUSA)
            trascorso += self.PAUSA
        yield comando("sonda", "memoria", byte=self.MODIFICA_BYTE,
                      nota="modifica di un blocco")
        yield attendi(min(self.CODA, max(0.0, durata - preludio - trascorso)),
                      nota="coda di osservazione")
        yield chiudi("sonda")


class CaricamentoSoftware(SequenzaAttacco):
    ramo = "percorso-di-caricamento"
    nome = "caricamento di software a bordo"
    firma = ("comando software assente dalla fase nominale",
             "messaggi lunghi e segmentati: dim_media e dim_massima sopra il profilo",
             "scrittura e attivazione a bordo a ogni segmento, non nella coda")

    SEGMENTO = 50_000
    PAUSA = 6.0
    SEGMENTI_MINIMI = 4
    CODA = 30.0

    def attacco(self, ric: Ricognizione, durata: float) -> Iterator[Azione]:
        yield apri("carico", identita=self.identita_da_dichiarare(ric))
        preludio = 3 * (ric.cadenza_osservata_s or 5.0)
        for _ in range(3):
            yield comando("carico", "test", byte=8)
            yield attendi(ric.cadenza_osservata_s or 5.0)
        disponibile = max(0.0, durata - preludio - self.CODA)
        segmenti = max(self.SEGMENTI_MINIMI, int(disponibile / self.PAUSA))
        trascorso = 0.0
        for i in range(segmenti):
            yield comando("carico", "software", byte=self.SEGMENTO,
                          nota=f"segmento {i + 1} di {segmenti}")
            yield attendi(self.PAUSA)
            trascorso += self.PAUSA
        yield attendi(min(self.CODA, max(0.0, durata - preludio - trascorso)),
                      nota="coda di osservazione")
        yield chiudi("carico")


class VocabolarioLegittimo(SequenzaAttacco):
    ramo = "vocabolario-legittimo"
    nome = "attacco col vocabolario delle stazioni"
    firma = ("nessun fuori-catalogo solo con telemetria nel carico nominale",
             "dimensione dal carico, ma sessioni più brevi e ritmo non sempre imitato",
             "identità secondo la strategia dichiarata")

    AMMESSI = ("housekeeping", "funzione", "test", "memoria", "scarica")

    richiede_esplorazione = True

    def esplorazione(self, ric: Ricognizione) -> Iterator[Azione]:
        yield ascolta(self.TETTO_ASCOLTO, obiettivo="identita",
                      nota="ascolto passivo del vocabolario")

    def attacco(self, ric: Ricognizione, durata: float) -> Iterator[Azione]:
        yield apri("coperta", identita=self.identita_da_dichiarare(ric),
                   nota="sessione con il vocabolario delle stazioni")
        cadenza = ric.cadenza_osservata_s or 5.0
        trascorso = 0.0
        while trascorso < durata - 5.0:
            yield comando("coperta", self.caso.choice(self.AMMESSI),
                          byte=ric.dimensione_tipica or 8,
                          nota="comando del vocabolario delle stazioni")
            yield attendi(cadenza)
            trascorso += cadenza
        yield chiudi("coperta")


class Dormiente(SequenzaAttacco):
    ramo = "dormiente"
    nome = "presente e inattivo"
    firma = ("nessun allarme atteso: controllo negativo",)

    def attacco(self, ric: Ricognizione, durata: float) -> Iterator[Azione]:
        yield apri("presenza", identita=self.identita_da_dichiarare(ric),
                   nota="sessione aperta senza comandi")
        yield attendi(max(0.0, durata - 1.0), nota="attesa senza azioni")
        yield chiudi("presenza")


class Adattivo(SequenzaAttacco):
    ramo = "adattivo"
    nome = "avversario che evita l'isteresi"
    firma = ("2 comandi alla cadenza osservata, poi 30 s di pausa, pari al contesto",
             "nessun comando fuori catalogo",
             "avversario white box: durata del contesto nota",
             "con identità rubata identita-di-altri e allarme entro 2 finestre")
    richiede_esplorazione = True

    PER_RAFFICA = 2
    PAUSA = 30.0

    def esplorazione(self, ric: Ricognizione) -> Iterator[Azione]:
        yield ascolta(self.TETTO_ASCOLTO, obiettivo="identita",
                      nota="ascolto passivo del catalogo")

    def attacco(self, ric: Ricognizione, durata: float) -> Iterator[Azione]:
        ammessi = tuple(n for n in ric.comandi_noti if n in CATALOGO)
        if not ammessi:
            return
        yield apri("coperta", identita=self.identita_da_dichiarare(ric),
                   nota="sessione sotto la soglia di rilevazione")
        cadenza = ric.cadenza_osservata_s or 5.0
        raffica = self.PER_RAFFICA * cadenza
        trascorso = 0.0
        while trascorso + raffica + self.PAUSA <= durata:
            for _ in range(self.PER_RAFFICA):
                yield comando("coperta", self.caso.choice(ammessi),
                              byte=ric.dimensione_tipica or 8, nota="raffica breve")
                yield attendi(cadenza)
                trascorso += cadenza
            yield attendi(self.PAUSA, nota="pausa più lunga del contesto")
            trascorso += self.PAUSA
        if durata - trascorso > 0:
            yield attendi(durata - trascorso, nota="attesa della fine")
        yield chiudi("coperta")


class IniezioneARaffiche(SequenzaAttacco):
    ramo = "iniezione-a-raffiche"
    nome = "iniezione di comandi in raffiche a distanza scelta"
    firma = ("raffiche istantanee di comandi del catalogo",
             "nessuna identità dichiarata",
             "avversario white box: larghezza della finestra nota")
    richiede_esplorazione = True

    PER_RAFFICA = 12
    RAFFICHE = 3
    DENTRO = 0.0625
    PERIODO = 45.0

    def esplorazione(self, ric: Ricognizione) -> Iterator[Azione]:
        yield ascolta(self.TETTO_ASCOLTO, obiettivo="identita",
                      nota="ascolto passivo del catalogo")

    def attacco(self, ric: Ricognizione, durata: float) -> Iterator[Azione]:
        ammessi = tuple(n for n in ric.comandi_noti if n in CATALOGO)
        if not ammessi:
            return
        distanza = self.strategie.distanza_raffiche_s
        dim = ric.dimensione_tipica or self.DIMENSIONE_DI_RIPIEGO
        gruppo = (self.RAFFICHE - 1) * distanza + self.DENTRO
        trascorso = 0.0
        while trascorso + gruppo + self.PERIODO <= durata:
            yield apri("iniezione", identita=self.identita_da_dichiarare(ric),
                       nota="una sessione per gruppo")
            for quale in range(self.RAFFICHE):
                for _ in range(self.PER_RAFFICA):
                    yield comando("iniezione", self.caso.choice(ammessi), byte=dim,
                                  nota="raffica istantanea")
                yield attendi(self.DENTRO, nota="raffica contenuta in una finestra")
                trascorso += self.DENTRO
                if quale < self.RAFFICHE - 1:
                    yield attendi(max(distanza - self.DENTRO, 0.0),
                                  nota=f"distanza fra raffiche: {distanza:g} s")
                    trascorso += max(distanza - self.DENTRO, 0.0)
            yield chiudi("iniezione", nota="chiusura del gruppo")
            yield attendi(self.PERIODO, nota="pausa fra gruppi")
            trascorso += self.PERIODO
        if durata - trascorso > 0:
            yield attendi(durata - trascorso, nota="attesa della fine")


SEQUENZE_ATTACCO: dict[str, type[SequenzaAttacco]] = {
    EsaurimentoSessioni.ramo: EsaurimentoSessioni,
    InondazioneDelCanale.ramo: InondazioneDelCanale,
    SaturazioneComandi.ramo: SaturazioneComandi,
    EsaurimentoMemoria.ramo: EsaurimentoMemoria,
    SessioniTrattenute.ramo: SessioniTrattenute,
    FalsificazioneIdentita.ramo: FalsificazioneIdentita,
    ReplayComandi.ramo: ReplayComandi,
    CaricamentoSoftware.ramo: CaricamentoSoftware,
    VerificaEModifica.ramo: VerificaEModifica,
    VocabolarioLegittimo.ramo: VocabolarioLegittimo,
    Dormiente.ramo: Dormiente,
    Adattivo.ramo: Adattivo,
    IniezioneARaffiche.ramo: IniezioneARaffiche,
}


def sequenza_attacco_per(ramo: str, durata: float, seme: int | None = None,
                 pazienza: float = 1.0,
                 ritmo_nominale_s: float | None = None,
                 strategie: Strategie | None = None) -> SequenzaAttacco | None:
    classe = SEQUENZE_ATTACCO.get(ramo)
    if classe is None:
        return None
    return classe(durata, seme, pazienza, ritmo_nominale_s, strategie)


class Esecutore(ABC):
    def __init__(self) -> None:
        self.ricognizione = Ricognizione()
        self.scadenza: float | None = None

    def scaduto(self) -> bool:
        return self.scadenza is not None and time.time() >= self.scadenza

    def osserva(self, ric: Ricognizione) -> None:
        self.ricognizione = ric

    @abstractmethod
    def esegui_azione(self, a: Azione) -> None:
        ...

    def chiusura(self) -> None:
        return None


class Registratore(Esecutore):
    def __init__(self, scoperte: Ricognizione | None = None) -> None:
        super().__init__()
        self.azioni: list[Azione] = []
        self.tempo = 0.0
        self.ascolti: list[str] = []
        self.scoperte = scoperte

    def esegui_azione(self, a: Azione) -> None:
        self.azioni.append(a)
        if a.tipo == TipoAzione.ASCOLTA:
            speso = a.secondi
            if self.scoperte is not None and self.scoperte.ascolto_speso_s is not None:
                speso = min(a.secondi, self.scoperte.ascolto_speso_s)
            self.tempo += speso
            self.ricognizione.ascolto_speso_s = speso
        elif a.tipo == TipoAzione.ATTENDI:
            self.tempo += a.secondi
        if a.tipo == TipoAzione.ASCOLTA and self.scoperte is not None:
            self.ascolti.append(a.obiettivo or "-")
            for campo, valore in vars(self.scoperte).items():
                if campo == "ascolto_speso_s":
                    continue
                if valore:
                    setattr(self.ricognizione, campo, valore)

    def di_tipo(self, tipo: str) -> list[Azione]:
        return [a for a in self.azioni if a.tipo == tipo]

    @property
    def sessioni_aperte(self) -> set[str]:
        aperte = {a.sessione for a in self.azioni if a.tipo == TipoAzione.APRI}
        return aperte - {a.sessione for a in self.azioni if a.tipo == TipoAzione.CHIUDI}

    @property
    def byte_inviati(self) -> int:
        return sum(a.byte * a.ripetizioni
                   for a in self.azioni if a.tipo in (TipoAzione.COMANDO, TipoAzione.RIMANDA))

    @property
    def comandi_inviati(self) -> int:
        return sum(a.ripetizioni for a in self.azioni
                   if a.tipo in (TipoAzione.COMANDO, TipoAzione.RIMANDA))


TIMEOUT_SOCKET = 5.0


class EsecutoreDiRete(Esecutore):
    def __init__(self, indirizzo: str, porta: int, bus: EventLog,
                 algoritmo: str = BBR, interfaccia: str = "eth0",
                 strategie: Strategie | None = None) -> None:
        super().__init__()
        self.strategie = strategie or Strategie()
        self.indirizzo = indirizzo
        self.porta = porta
        self.bus = bus
        self.algoritmo = algoritmo
        self.interfaccia = interfaccia
        self._socket: dict[str, socket.socket] = {}
        self._sequenza: dict[str, int] = {}
        self._verifiche = 0
        self.aperture_fallite = 0
        self.comandi_inviati = 0

    def _sequenza_di(self, sessione: str) -> int:
        n = self._sequenza.get(sessione, 0) + 1
        self._sequenza[sessione] = n
        return n

    def esegui_azione(self, a: Azione) -> None:
        match a.tipo:
            case TipoAzione.APRI:
                self._apri(a)
            case TipoAzione.COMANDO:
                self._comando(a)
            case TipoAzione.RIMANDA:
                self._rimanda(a)
            case TipoAzione.CHIUDI:
                self._chiudi(a.sessione)
            case TipoAzione.ASCOLTA:
                self._ascolta(a.secondi, a.obiettivo)
            case TipoAzione.ATTENDI:
                resto = (a.secondi if self.scadenza is None
                         else min(a.secondi, self.scadenza - time.time()))
                time.sleep(max(0.0, resto))

    def _ascolta(self, secondi: float, obiettivo: str = "") -> None:
        ric = self.ricognizione
        visti: list[tuple[float, str, str]] = []
        identita: dict[str, str] = {}
        dimensioni: list[int] = []
        catturati: list[bytes] = []
        avvio = time.monotonic()
        try:
            riass: dict[str, Riassemblatore] = {}
            for telaio in cattura_promiscua(self.interfaccia, secondi=secondi):
                seg = analizza_telaio(telaio)
                if seg is None or seg.porta_destinatario != self.porta:
                    continue
                if not seg.carico:
                    continue
                r = riass.setdefault(seg.flusso, Riassemblatore(
                    identificatori=IDENTIFICATORI_NOTI))
                for grezzo in r.alimenta(seg.carico):
                    try:
                        tc = decodifica_comando(grezzo)
                    except Exception:
                        continue
                    visti.append((time.time(), tc.nome, seg.ip_mittente))
                    ric.sequenza_osservata = tc.sequenza
                    if tc.dimensione:
                        dimensioni.append(int(tc.dimensione))
                    if tc.nome == "identita":
                        identita[seg.ip_mittente] = tc.dati.decode("utf-8", "replace")
                        if obiettivo == "identita":
                            raise _Trovato
                    elif obiettivo == "pacchetti":
                        catturati.append(grezzo)
                        if len(catturati) >= PACCHETTI_DA_CATTURARE:
                            raise _Trovato
        except _Trovato:
            pass
        except (RuntimeError, OSError, PermissionError) as errore:
            ric.ascolto_speso_s = time.monotonic() - avvio
            self.bus.scrivi(NODO_ATTACCO, {"azione": "ascolta",
                                           "esito": "non-possibile",
                                           "motivo": str(errore),
                                           "tetto_s": secondi,
                                           "speso_s": round(ric.ascolto_speso_s, 3)})
            return

        if identita:
            ric.identita_osservata = self._vittima(identita, visti)
        nomi = {n for _, n, _ in visti}
        if nomi:
            ric.comandi_noti = tuple(sorted(nomi))
        if catturati:
            ric.pacchetti_catturati = tuple(catturati)
        if dimensioni:
            ric.dimensione_tipica = (
                int(statistics.median(dimensioni))
                if self.strategie.dimensione_comandi == "dal-carico"
                else max(dimensioni))
        cadenza = self._cadenza_di(visti, identita, ric.identita_osservata)
        if cadenza is not None:
            ric.cadenza_osservata_s = cadenza
        ric.ascolto_speso_s = time.monotonic() - avvio
        self.bus.scrivi(NODO_ATTACCO, {
            "azione": "ascolta", "esito": "fatto", "secondi": secondi,
            "speso_s": round(ric.ascolto_speso_s, 3),
            "comandi_visti": len(visti), "identita_viste": len(identita),
            "pacchetti_catturati": len(catturati)})

    def _apri(self, a: Azione) -> None:
        try:
            s, _ = crea_socket_client(self.indirizzo, self.porta, self.algoritmo,
                                      timeout=TIMEOUT_SOCKET)
        except OSError:
            self.aperture_fallite += 1
            self.bus.scrivi(NODO_ATTACCO, {"azione": "apri", "sessione": a.sessione,
                                           "esito": "rifiutata"})
            return
        self._socket[a.sessione] = s
        if a.identita:
            try:
                s.sendall(codifica_comando("identita",
                                               self._sequenza_di(a.sessione),
                                               a.identita.encode("utf-8")))
            except OSError:
                pass
        self.bus.scrivi(NODO_ATTACCO, {"azione": "apri", "sessione": a.sessione,
                                       "identita": a.identita, "esito": "aperta"})

    def _comando(self, a: Azione) -> None:
        if self._socket.get(a.sessione) is None:
            return
        if a.comando == "identita":
            dati = (a.identita or "?").encode("utf-8")
        elif a.comando == "verifica":
            dati = richiesta_di_verifica(self._verifiche * AREA_DI_VERIFICA_BYTE,
                                         AREA_DI_VERIFICA_BYTE)
            self._verifiche += 1
        else:
            dati = os.urandom(a.byte) if a.byte else b""
        for _ in range(max(1, a.ripetizioni)):
            if self.scaduto() or not self._scrivi(a, dati):
                return

    def _vittima(self, identita: dict[str, str],
                 visti: list[tuple[float, str, str]]) -> str:
        strategia = self.strategie.vittima
        if strategia in identita.values():
            return strategia
        quanti: dict[str, int] = {}
        for _, _, ip in visti:
            nome = identita.get(ip)
            if nome:
                quanti[nome] = quanti.get(nome, 0) + 1
        if strategia == "piu-attiva" and quanti:
            return max(sorted(quanti), key=lambda n: quanti[n])
        if strategia == "meno-attiva" and quanti:
            return min(sorted(quanti), key=lambda n: quanti[n])
        return sorted(identita.values())[0]

    def _cadenza_di(self, visti: list[tuple[float, str, str]],
                    identita: dict[str, str], bersaglio: str) -> float | None:
        istanti = [t for t, _, _ in visti]
        if self.strategie.imita == "una-stazione" and bersaglio:
            mittente = next((ip for ip, nome in sorted(identita.items())
                             if nome == bersaglio), None)
            if mittente is not None:
                suoi = [t for t, _, ip in visti if ip == mittente]
                if len(suoi) >= 2:
                    istanti = suoi
        if len(istanti) < 2:
            return None
        intervalli = [b - a for a, b in zip(istanti, istanti[1:])]
        return sum(intervalli) / len(intervalli) if intervalli else None

    def _svuota(self, sessione: str) -> int:
        s = self._socket.get(sessione)
        if s is None:
            return 0
        letti = 0
        try:
            s.setblocking(False)
            while True:
                dati = s.recv(65536)
                if not dati:
                    break
                letti += len(dati)
        except (BlockingIOError, OSError):
            pass
        finally:
            try:
                s.settimeout(TIMEOUT_SOCKET)
            except OSError:
                pass
        return letti

    def _rimanda(self, a: Azione) -> None:
        s = self._socket.get(a.sessione)
        if s is None or not a.grezzo:
            return
        try:
            s.sendall(a.grezzo)
            self.comandi_inviati += 1
        except OSError:
            self._chiudi(a.sessione)
            return
        letti = self._svuota(a.sessione)
        self.bus.scrivi(NODO_ATTACCO, {"azione": "rimanda", "sessione": a.sessione,
                                       "byte": len(a.grezzo), "svuotati_byte": letti,
                                       "esito": "inviato", "nota": a.nota})

    def _scrivi(self, a: Azione, dati: bytes) -> bool:
        s = self._socket.get(a.sessione)
        if s is None:
            return False
        self._svuota(a.sessione)
        sequenza = a.sequenza if a.sequenza is not None else self._sequenza_di(a.sessione)
        try:
            if a.comando in CATALOGO:
                s.sendall(codifica_comando(a.comando, sequenza, dati))
            else:
                s.sendall(codifica_grezzo(SERVIZIO_FUNZIONE,
                                          SOTTOTIPO_INESISTENTE, sequenza, dati))
            self.comandi_inviati += 1
        except OSError:
            self._chiudi(a.sessione)
            return False
        return True

    def _chiudi(self, sessione: str, subito: bool = False) -> None:
        s = self._socket.pop(sessione, None)
        if s is None:
            return
        try:
            if subito:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                             struct.pack("ii", 1, 0))
            s.close()
        except OSError:
            pass

    def chiusura(self) -> None:
        subito = self.scaduto()
        for sessione in list(self._socket):
            self._chiudi(sessione, subito)


def attendi_ordine(percorso: str | Path, adesso: float | None = None,
                   attesa_massima: float = 3600.0,
                   pausa: float = 1.0) -> dict | None:
    percorso = Path(percorso)
    scadenza = (adesso if adesso is not None else time.time()) + attesa_massima
    while time.time() < scadenza:
        try:
            if percorso.exists():
                return json.loads(percorso.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        time.sleep(pausa)
    return None


class AttackerGroundUnit:
    def __init__(self, bus: EventLog, ramo: str = "-",
                 conoscenza: str = "informata", esecutore: Esecutore | None = None,
                 identita_bersaglio: str = "ground1",
                 comandi_al_minuto: float = 12.0, seme: int | None = None,
                 pazienza: float = 1.0, ritmo_nominale_s: float | None = None,
                 strategie: Strategie | None = None) -> None:
        self.strategie = strategie or Strategie()
        self.bus = bus
        self.ramo = ramo
        self.conoscenza = conoscenza
        self.esecutore = esecutore
        self.identita_bersaglio = identita_bersaglio
        self.comandi_al_minuto = comandi_al_minuto
        self.seme = seme
        self.pazienza = pazienza
        self.ritmo_nominale_s = ritmo_nominale_s
        self._attivo = True

    def ricognizione(self) -> Ricognizione:
        if self.conoscenza == "informata":
            return Ricognizione.informata(self.identita_bersaglio,
                                          self.comandi_al_minuto)
        return Ricognizione()

    def esegui_sequenza_attacco(self, durata: float) -> int:
        sequenza_attacco = sequenza_attacco_per(self.ramo, durata, self.seme, self.pazienza,
                                self.ritmo_nominale_s, self.strategie)
        if sequenza_attacco is None or self.esecutore is None:
            self.bus.scrivi(NODO_ATTACCO, {
                "evento": "nessuna-sequenza", "ramo": self.ramo})
            return 0
        ric = self.ricognizione()
        self.esecutore.osserva(ric)
        self.esecutore.scadenza = time.time() + durata
        self.bus.scrivi(NODO_ATTACCO, {
            "evento": "inizio", "ramo": self.ramo, "sequenza_attacco": sequenza_attacco.nome,
            "conoscenza": self.conoscenza, "durata_s": durata,
            "pazienza": self.pazienza,
            "ritmo_nominale_s": self.ritmo_nominale_s,
            "firma_attesa": list(sequenza_attacco.firma)})
        fatte = 0
        alla_scadenza = False
        for azione in sequenza_attacco.azioni(ric):
            if not self._attivo:
                break
            if self.esecutore.scaduto():
                alla_scadenza = True
                break
            self.esecutore.esegui_azione(azione)
            fatte += 1
        self.esecutore.chiusura()
        self.bus.scrivi(NODO_ATTACCO, {"evento": "fine", "ramo": self.ramo,
                                       "azioni": fatte,
                                       "interrotta_alla_scadenza": alla_scadenza})
        return fatte

    def esegui(self, durata: float | None = None,
               ordine: str | Path | None = None) -> None:
        inizio = time.time()
        self.bus.scrivi("nodo.stato", {"ruolo": "attacker", "ramo": self.ramo,
                                       "conoscenza": self.conoscenza})
        if ordine is not None and self.ramo != "-":
            dati = attendi_ordine(ordine)
            if dati is not None and self._attivo:
                ritardo = float(dati.get("inizio", 0.0)) - time.time()
                if ritardo > 0:
                    time.sleep(ritardo)
                finestra = float(dati.get("fine", 0.0)) - time.time()
                if finestra > 0:
                    self.esegui_sequenza_attacco(finestra)
        while self._attivo:
            if durata is not None and time.time() - inizio >= durata:
                break
            time.sleep(1.0)

    def ferma(self, *_: object) -> None:
        self._attivo = False
        if self.esecutore is not None:
            self.esecutore.chiusura()


def main() -> None:
    ap = argparse.ArgumentParser(description="Nodo attaccante del banco")
    ap.add_argument("--vista", required=True, help="vista locale dell'attaccante, JSON Lines")
    ap.add_argument("--satellite", default="10.0.0.10", help="indirizzo del satellite")
    ap.add_argument("--porta", type=int, default=PORTA_PREDEFINITA,
                    help="porta TCP del servizio di bordo")
    ap.add_argument("--ramo", default="-", help="; ".join(sorted(SEQUENZE_ATTACCO)))
    ap.add_argument("--conoscenza", default="informata",
                    choices=("informata", "esplorativa"), help="conoscenza iniziale del sistema")
    ap.add_argument("--identita-bersaglio", default="ground1", help="stazione da imitare")
    ap.add_argument("--comandi-al-minuto", type=float, default=12.0,
                    help="cadenza della stazione imitata, comandi/minuto")
    ap.add_argument("--congestione", default=BBR, help="algoritmo di controllo della congestione")
    ap.add_argument("--ordine", default=None,
                    help="file in cui l'orchestratore scrive la finestra d'attacco")
    ap.add_argument("--durata", type=float, default=None,
                    help="durata del nodo, s; senza valore fino all'arresto")
    ap.add_argument("--seme", type=int, default=None, help="seme del generatore")
    ap.add_argument("--ritmo-nominale", type=float, default=None,
                    help="comandi/s del carico legittimo, tetto dell'attacco con --pazienza")
    ap.add_argument("--pazienza", type=float, default=1.0,
                    help="rallentamento del ramo, 1 = ritmo nominale")
    ap.add_argument("--identita-dichiarata", default="nessuna",
                    choices=("nessuna", "rubata", "fittizia"),
                    help="identità dichiarata all'apertura delle sessioni d'attacco")
    ap.add_argument("--identita-esplorazione", default="segnaposto",
                    choices=("segnaposto", "fittizia"),
                    help='identità dichiarata nel sondaggio; segnaposto dichiara "?"')
    ap.add_argument("--imita", default="aggregata",
                    choices=("aggregata", "una-stazione"),
                    help="cadenza imitata, del mezzo o di una stazione")
    ap.add_argument("--dimensione-comandi", default="fissa-16",
                    choices=("fissa-16", "dal-carico"),
                    help="dimensione dei comandi, 16 B o quella osservata")
    ap.add_argument("--vittima", default="prima-alfabetica",
                    help="prima-alfabetica | piu-attiva | meno-attiva | un nome")
    ap.add_argument("--jitter", default="no", choices=("no", "come-il-carico"),
                    help="attese con lo stesso scarto del carico legittimo")
    ap.add_argument("--forma-sessioni", default="continua",
                    choices=("continua", "a-raffiche"),
                    help="sessioni per tutta la finestra o a raffiche")
    ap.add_argument("--durata-sessione", type=float, default=150.0,
                    help="durata delle sessioni a raffiche, s")
    ap.add_argument("--pausa-sessione", type=float, default=25.0,
                    help="pausa fra sessioni a raffiche, s")
    ap.add_argument("--variabilita-sessione", type=float, default=0.4,
                    help="scarto relativo di durata e pausa delle sessioni")
    ap.add_argument("--distanza-raffiche", type=float, default=1.5,
                    help="distanza fra 2 raffiche di iniezione-a-raffiche, s")
    ap.add_argument("--variabilita", type=float, default=0.25,
                    help="scarto relativo delle attese con jitter")
    args = ap.parse_args()

    strategie = Strategie(
        identita_dichiarata=args.identita_dichiarata,
        identita_esplorazione=args.identita_esplorazione,
        imita=args.imita,
        dimensione_comandi=args.dimensione_comandi,
        vittima=args.vittima,
        jitter=args.jitter,
        variabilita=args.variabilita,
        forma_sessioni=args.forma_sessioni,
        distanza_raffiche_s=args.distanza_raffiche,
        durata_sessione_s=args.durata_sessione,
        pausa_sessione_s=args.pausa_sessione,
        variabilita_sessione=args.variabilita_sessione)
    bus = EventLog(args.vista)
    esecutore = EsecutoreDiRete(args.satellite, args.porta, bus, args.congestione,
                                strategie=strategie)
    nodo = AttackerGroundUnit(bus, args.ramo, args.conoscenza, esecutore,
                              args.identita_bersaglio, args.comandi_al_minuto,
                              args.seme, args.pazienza, args.ritmo_nominale,
                              strategie=strategie)
    signal.signal(signal.SIGTERM, nodo.ferma)
    signal.signal(signal.SIGINT, nodo.ferma)
    try:
        nodo.esegui(args.durata, args.ordine)
    finally:
        esecutore.chiusura()
        bus.chiudi()


if __name__ == "__main__":
    main()
