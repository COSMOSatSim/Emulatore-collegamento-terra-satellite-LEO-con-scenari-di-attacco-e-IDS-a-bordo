from __future__ import annotations

import argparse
import random
import threading
import time
from collections.abc import Callable
from pathlib import Path

from common.protocol import (SERVIZIO_ARCHIVIO, SOTTOTIPO_TRASFERIMENTO,
                             TEMPO_MASSIMO_TRASFERIMENTO, Riassemblatore,
                             codifica_comando, decodifica_telemetria,
                             quote_di_trasferimento, richiesta_di_trasferimento)
from common.transport import crea_socket_client
from common.visibilita import Visibilita, annuncia
from model.config import BBR, WorkloadProfile
from model.events import APP_COMANDO, APP_SESSIONE, EventLog


class SessionClient:
    def __init__(self, indirizzo: str, porta: int, algoritmo: str = BBR) -> None:
        self.indirizzo = indirizzo
        self.porta = porta
        self.algoritmo = algoritmo
        self.sock = None
        self.esito = None
        self._riass = Riassemblatore()
        self._sequenza = 0

    def apri(self, attesa_massima: float = 120.0) -> None:
        scadenza = time.monotonic() + attesa_massima
        while True:
            try:
                self.sock, self.esito = crea_socket_client(self.indirizzo, self.porta,
                                                           self.algoritmo)
                break
            except OSError:
                if time.monotonic() >= scadenza:
                    raise
                time.sleep(1.0)
        self.sock.settimeout(0.2)

    def invia(self, comando: str, dati: bytes = b"") -> int:
        self._sequenza = (self._sequenza + 1) % 0x4000
        grezzo = codifica_comando(comando, self._sequenza, dati)
        self.sock.sendall(grezzo)
        return self._sequenza

    def ricevi(self) -> list[tuple[int, int, int, bytes]]:
        try:
            pezzo = self.sock.recv(65536)
        except (TimeoutError, OSError):
            return []
        if not pezzo:
            return []
        return [decodifica_telemetria(g) for g in self._riass.alimenta(pezzo)]

    def attendi_risposta(self, tempo_massimo: float = 5.0) -> bool:
        scadenza = time.monotonic() + tempo_massimo
        while time.monotonic() < scadenza:
            for servizio, sottotipo, _, _ in self.ricevi():
                if (servizio, sottotipo) == (1, 7):
                    return True
        return False

    def trasferisci_tutto(self, kb: float,
                      tempo_massimo: float = TEMPO_MASSIMO_TRASFERIMENTO,
                      su_quota: Callable[[int], None] | None = None) -> int:
        ricevuti = 0
        for quota in quote_di_trasferimento(kb):
            parte = self.trasferisci(quota, tempo_massimo)
            ricevuti += parte
            if su_quota is not None:
                su_quota(parte)
        return ricevuti

    def trasferisci(self, kb: float, tempo_massimo: float = TEMPO_MASSIMO_TRASFERIMENTO) -> int:
        self.invia("scarica", richiesta_di_trasferimento(kb))
        ricevuti = 0
        scadenza = time.monotonic() + tempo_massimo
        while time.monotonic() < scadenza:
            for servizio, sottotipo, _, dati in self.ricevi():
                if (servizio, sottotipo) == (SERVIZIO_ARCHIVIO, SOTTOTIPO_TRASFERIMENTO):
                    ricevuti += len(dati)
                elif (servizio, sottotipo) == (1, 7):
                    return ricevuti
        return ricevuti

    def chiudi(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None


class LegitimateGroundUnit:
    def __init__(self, indirizzo: str, porta: int, bus: EventLog,
                 carico: WorkloadProfile | None = None, algoritmo: str = BBR,
                 seme: int | None = None, identita: str = "ground",
                 visibilita: Visibilita | None = None) -> None:
        self.identita = identita
        self.client = SessionClient(indirizzo, porta, algoritmo)
        self.bus = bus
        self.carico = carico or WorkloadProfile()
        self._rnd = random.Random(seme)
        self._rnd_tm = random.Random(None if seme is None else seme + 1)
        self._attivo = True
        self.visibilita = visibilita or Visibilita()

    def _prossimo_comando(self) -> str:
        nomi = list(self.carico.composizione)
        pesi = [self.carico.composizione[n] for n in nomi]
        return self._rnd.choices(nomi, weights=pesi, k=1)[0]

    def _prossima_attesa(self) -> float:
        base = 60.0 / max(self.carico.comandi_al_minuto, 0.01)
        scarto = base * self.carico.variabilita
        return max(0.05, self._rnd.gauss(base, scarto))

    def _durata_sessione(self) -> float:
        base = max(1.0, self.carico.durata_sessione_s)
        return max(5.0, self._rnd.gauss(base, base * self.carico.variabilita_sessione))

    def _pausa_fra_sessioni(self) -> float:
        base = max(0.0, self.carico.pausa_fra_sessioni_s)
        return max(0.0, self._rnd.gauss(base, base * 0.5))

    def _carico_di(self, comando: str) -> bytes:
        if comando == "identita":
            return self.identita.encode("utf-8")
        return b"\x00" * (64 if comando == "memoria" else 8)

    def _esegui_sessione(self, fine_sessione: float,
                         fine_tutto: float) -> int:
        self.client.apri()
        self.bus.scrivi(APP_SESSIONE, {
            "evento": "apertura", "ruolo": "ground", "identita": self.identita,
            "congestione_richiesta": self.client.algoritmo,
            "congestione_effettiva": getattr(self.client.esito, "effettivo", None)})
        self.client.invia("identita", self.identita.encode("utf-8"))
        inviati = 0
        inizio = time.time()
        try:
            while (self._attivo and time.time() < fine_sessione
                   and time.time() < fine_tutto):
                comando = self._prossimo_comando()
                dati = self._carico_di(comando)
                invio = time.time()
                seq = self.client.invia(comando, dati)
                inviati += 1
                risposto = self.client.attendi_risposta()
                latenza = round((time.time() - invio) * 1000.0, 3) if risposto else None
                self.bus.scrivi(APP_COMANDO, {
                    "ruolo": "ground", "comando": comando, "sequenza": seq,
                    "dimensione": len(dati), "inviato": round(invio, 6),
                    "latenza_ms": latenza,
                    "esito": "risposto" if risposto else "senza-risposta"})
                time.sleep(self._prossima_attesa())
        except OSError:
            pass
        finally:
            self.client.chiudi()
            self.bus.scrivi(APP_SESSIONE, {
                "evento": "chiusura", "ruolo": "ground",
                "durata_s": round(time.time() - inizio, 3)})
        return inviati

    def esegui(self, durata: float) -> int:
        inviati = 0
        fine_tutto = time.time() + durata
        while self._attivo and time.time() < fine_tutto:
            if not self._attendi_finestra(fine_tutto):
                break
            fine_sessione = min(fine_tutto, time.time() + self._durata_sessione())
            chiusura = self.visibilita.fine_finestra(self.identita, time.time())
            if chiusura is not None:
                fine_sessione = min(fine_sessione, chiusura)
            try:
                inviati += self._esegui_sessione(fine_sessione, fine_tutto)
            except OSError:
                pass
            if not self._attivo:
                break
            pausa = self._pausa_fra_sessioni()
            if time.time() + pausa >= fine_tutto:
                break
            time.sleep(pausa)
        return inviati

    def _attendi_finestra(self, fine_tutto: float) -> bool:
        if not self.visibilita.conosce(self.identita):
            return True
        while self._attivo:
            adesso = time.time()
            if adesso >= fine_tutto:
                return False
            if self.visibilita.in_visibilita(self.identita, adesso):
                return True
            apertura = self.visibilita.prossima_apertura(self.identita, adesso)
            if apertura is None or apertura >= fine_tutto:
                return False
            time.sleep(min(1.0, max(0.05, apertura - adesso)))
        return False

    def telemetria(self, durata: float) -> int:
        kb = self.carico.telemetria_kb
        if kb <= 0:
            return 0
        fatti = 0
        fine_tutto = time.time() + durata
        while self._attivo:
            attesa = max(5.0, self._rnd_tm.gauss(self.carico.telemetria_ogni_s,
                                                 self.carico.telemetria_ogni_s * 0.2))
            if time.time() + attesa >= fine_tutto:
                break
            time.sleep(attesa)
            if not self._attivo or not self._attendi_finestra(fine_tutto):
                break
            client = SessionClient(self.client.indirizzo, self.client.porta,
                                   self.client.algoritmo)
            inizio = time.time()
            arrivati: list[int] = []
            errore = None
            try:
                client.apri(attesa_massima=10.0)
                self.bus.scrivi(APP_SESSIONE, {"evento": "apertura", "ruolo": "telemetria",
                                               "identita": self.identita})
                client.invia("identita", self.identita.encode("utf-8"))
                client.attendi_risposta()
                client.trasferisci_tutto(kb, su_quota=arrivati.append)
                fatti += 1
            except Exception as e:
                errore = f"{type(e).__name__}: {e}"
            finally:
                client.chiudi()
                self.bus.scrivi(APP_SESSIONE, {
                    "evento": "chiusura", "ruolo": "telemetria",
                    "durata_s": round(time.time() - inizio, 3),
                    "byte_ricevuti": sum(arrivati), "quote": len(arrivati),
                    "byte_richiesti": int(kb) * 1024,
                    **({"errore": errore} if errore else {})})
        return fatti

    def ferma(self, *_: object) -> None:
        self._attivo = False


def leggi_composizione(testo: str | None, predefinita: dict[str, float]) -> dict[str, float]:
    if not testo:
        return dict(predefinita)
    pesi = {}
    for voce in testo.split(","):
        nome, _, peso = voce.partition("=")
        pesi[nome.strip()] = float(peso)
    return pesi


def main() -> None:
    ap = argparse.ArgumentParser(description="Ground unit legittima")
    ap.add_argument("--satellite", required=True, help="indirizzo del satellite")
    ap.add_argument("--porta", type=int, default=5000, help="porta TCP del servizio di bordo")
    ap.add_argument("--vista", required=True, help="vista locale della stazione, JSON Lines")
    ap.add_argument("--durata", type=float, default=3600.0, help="durata del carico, s")
    predefinito = WorkloadProfile()
    ap.add_argument("--comandi-al-minuto", type=float, default=predefinito.comandi_al_minuto,
                    help="cadenza dei comandi, comandi/minuto")
    ap.add_argument("--variabilita", type=float, default=predefinito.variabilita,
                    help="scarto relativo degli intervalli fra comandi")
    ap.add_argument("--durata-sessione", type=float, default=predefinito.durata_sessione_s,
                    help="durata di una sessione, s")
    ap.add_argument("--variabilita-sessione", type=float,
                    default=predefinito.variabilita_sessione,
                    help="scarto relativo della durata della sessione")
    ap.add_argument("--pausa-fra-sessioni", type=float,
                    default=predefinito.pausa_fra_sessioni_s,
                    help="pausa fra chiusura e riapertura, s")
    ap.add_argument("--composizione", default=None,
                    help="pesi dei comandi, per esempio test=0.24,funzione=0.28")
    ap.add_argument("--telemetria-kb", type=float, default=predefinito.telemetria_kb,
                    help="telemetria trasferita per giro, kB; 0 senza telemetria")
    ap.add_argument("--telemetria-ogni", type=float, default=predefinito.telemetria_ogni_s,
                    help="periodo della telemetria, s")
    ap.add_argument("--congestione", default=BBR, help="algoritmo di controllo della congestione")
    ap.add_argument("--seme", type=int, default=None, help="seme del generatore")
    ap.add_argument("--identita", default="ground", help="nome d'identità dichiarato")
    ap.add_argument("--visibilita", default=None,
                    help="calendario dei passaggi della stazione")
    args = ap.parse_args()

    bus = EventLog(args.vista)
    carico = WorkloadProfile(comandi_al_minuto=args.comandi_al_minuto,
                             variabilita=args.variabilita,
                             durata_sessione_s=args.durata_sessione,
                             variabilita_sessione=args.variabilita_sessione,
                             pausa_fra_sessioni_s=args.pausa_fra_sessioni,
                             composizione=leggi_composizione(args.composizione,
                                                             predefinito.composizione),
                             telemetria_kb=args.telemetria_kb,
                             telemetria_ogni_s=args.telemetria_ogni)
    visibilita = Visibilita.da_file(args.visibilita)
    if args.visibilita:
        annuncia(bus, visibilita, args.identita)
    unita = LegitimateGroundUnit(args.satellite, args.porta, bus, carico,
                                 args.congestione, args.seme, args.identita,
                                 visibilita)
    if carico.telemetria_kb > 0:
        threading.Thread(target=unita.telemetria, args=(args.durata,), daemon=True).start()
    try:
        inviati = unita.esegui(args.durata)
        print(f"comandi inviati: {inviati}")
    finally:
        bus.chiudi()


if __name__ == "__main__":
    main()
