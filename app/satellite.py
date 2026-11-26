from __future__ import annotations

import argparse
import hashlib
import socket
import socketserver
import threading
import time
from pathlib import Path

from common.identita import RegistroIdentita
from common.visibilita import Visibilita, annuncia
from common.protocol import (BYTE_PER_PACCHETTO_DI_TRASFERIMENTO, CATALOGO, Riassemblatore,
                             SERVIZIO_ARCHIVIO, SERVIZIO_HOUSEKEEPING,
                             SERVIZIO_MEMORIA, SOTTOTIPO_RAPPORTO_VERIFICA,
                             SOTTOTIPO_TRASFERIMENTO, VERIFICA_MASSIMA_BYTE,
                             area_richiesta, chilobyte_richiesti,
                             codifica_telemetria, decodifica_comando)
from common.transport import leggi_congestione
from ids.alarm import leggi_stato_allarme
from model.events import (APP_COMANDO, APP_SESSIONE, BORDO_EVENTO,
                          FINESTRA_SEQUENZA, EventLog)

PORTA_PREDEFINITA = 5000


class PeerRegistry:
    def __init__(self) -> None:
        self._voci: dict[str, dict] = {}
        self.identita = RegistroIdentita()
        self._lock = threading.Lock()

    def _voce(self, peer: str) -> dict:
        return self._voci.setdefault(peer, {
            "peer": peer, "identita": None, "prima_volta": time.time(),
            "comandi": 0, "ultima_sequenza": None, "salti": 0, "sessioni": 0,
        })

    def registra(self, peer: str, identita: str | None = None) -> dict:
        with self._lock:
            voce = self._voce(peer)
        if identita and not voce.get("identita"):
            self.dichiara(peer, identita)
        return voce

    def dichiara(self, peer: str, identita: str) -> dict:
        nota = self.identita.dichiara(peer, identita)
        with self._lock:
            self._voce(peer)["identita"] = nota["identita"]
        return nota

    def identita_di(self, peer: str) -> str | None:
        return self.identita.di(peer)

    def origini_di(self, identita: str | None) -> int:
        return self.identita.origini(identita)

    def nota_comando(self, peer: str, sequenza: int) -> bool:
        with self._lock:
            voce = self._voce(peer)
            voce["comandi"] += 1
            prec = voce["ultima_sequenza"]
            anomalo = False
            if prec is not None:
                avanti = (sequenza - prec) % FINESTRA_SEQUENZA
                if avanti == 0 or avanti > FINESTRA_SEQUENZA // 2:
                    anomalo = True
                    voce["salti"] += 1
            voce["ultima_sequenza"] = sequenza
            return anomalo

    def elenco(self) -> list[dict]:
        with self._lock:
            return [dict(v) for v in self._voci.values()]


class CommandCatalog:
    def __init__(self, ammessi: set[str] | None = None) -> None:
        self.ammessi = ammessi or set(CATALOGO)

    def valido(self, nome: str) -> bool:
        return nome in self.ammessi


class OnboardStorage:
    def __init__(self, cartella: str | Path, limite_mb: float = 64.0) -> None:
        self.cartella = Path(cartella)
        self.cartella.mkdir(parents=True, exist_ok=True)
        self.limite_byte = int(limite_mb * 1024 * 1024)
        self.usato = 0
        self._n = 0
        self._lock = threading.Lock()

    def scrivi(self, dati: bytes) -> tuple[bool, str]:
        with self._lock:
            if self.usato + len(dati) > self.limite_byte:
                return False, "spazio esaurito"
            self._n += 1
            (self.cattura_nome()).write_bytes(dati)
            self.usato += len(dati)
            return True, "scritto"

    def cattura_nome(self) -> Path:
        return self.cartella / f"blocco_{self._n:06d}.bin"

    def deposita_immagine(self, dati: bytes) -> tuple[bool, str, Path | None]:
        with self._lock:
            if self.usato + len(dati) > self.limite_byte:
                return False, "spazio esaurito", None
            self._n += 1
            percorso = self.cartella / f"immagine_{self._n:06d}.bin"
            percorso.write_bytes(dati)
            self.usato += len(dati)
            return True, "depositata", percorso

    def verifica(self, da: int, quanti: int) -> tuple[int, str]:
        quanti = max(0, min(quanti, VERIFICA_MASSIMA_BYTE))
        if quanti == 0:
            return 0, ""
        with self._lock:
            blocchi = sorted(self.cartella.glob("*.bin"))
        impronta = hashlib.sha256()
        letti = 0
        salta = max(0, da)
        for f in blocchi:
            if letti >= quanti:
                break
            try:
                dati = f.read_bytes()
            except OSError:
                continue
            if salta >= len(dati):
                salta -= len(dati)
                continue
            pezzo = dati[salta:salta + (quanti - letti)]
            salta = 0
            impronta.update(pezzo)
            letti += len(pezzo)
        return letti, impronta.hexdigest()[:16]

    @property
    def libero_mb(self) -> float:
        return (self.limite_byte - self.usato) / 1048576.0


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        srv: "TelemetryCommandService" = self.server.servizio
        peer = f"{self.client_address[0]}"
        sessione = f"{self.client_address[0]}:{self.client_address[1]}"
        srv.registro.registra(peer)
        srv.bus.scrivi(APP_SESSIONE, {
            "evento": "apertura", "sessione": sessione, "peer": peer,
            "congestione": leggi_congestione(self.request)})
        srv.aggiungi_client(self.request)
        riass = Riassemblatore()
        try:
            while True:
                pezzo = self.request.recv(8192)
                if not pezzo:
                    break
                for grezzo in riass.alimenta(pezzo):
                    srv.gestisci_pacchetto(grezzo, peer, sessione, self.request)
        except OSError:
            pass
        finally:
            srv.togli_client(self.request)
            srv.bus.scrivi(APP_SESSIONE, {"evento": "chiusura", "sessione": sessione,
                                          "peer": peer})


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TelemetryCommandService:
    TETTO_ATTIVAZIONE = 256
    TEMPO_MASSIMO_ATTIVAZIONE = 2.0

    def __init__(self, bus: EventLog, porta: int = PORTA_PREDEFINITA,
                 archivio: OnboardStorage | None = None,
                 periodo_beacon: float = 5.0, stato_allarme: str | None = None,
                 visibilita: Visibilita | None = None) -> None:
        self.bus = bus
        self.porta = porta
        self.registro = PeerRegistry()
        self.catalogo = CommandCatalog()
        self.visibilita = visibilita or Visibilita()
        self.archivio = archivio
        self.periodo_beacon = periodo_beacon
        self.stato_allarme_file = stato_allarme
        self._clients: set[socket.socket] = set()
        self._scritture: dict[socket.socket, threading.Lock] = {}
        self._lock = threading.Lock()
        self._sequenza_tm = 0
        self._stato_allarme = {"allarme": False, "punteggio": 0.0}
        self._server: _Server | None = None

    def aggiungi_client(self, s: socket.socket) -> None:
        with self._lock:
            self._clients.add(s)
            self._scritture[s] = threading.Lock()

    def togli_client(self, s: socket.socket) -> None:
        with self._lock:
            self._clients.discard(s)
            self._scritture.pop(s, None)

    def _invia(self, sock: socket.socket, pacchetto: bytes) -> None:
        with self._lock:
            lucchetto = self._scritture.get(sock)
        if lucchetto is None:
            sock.sendall(pacchetto)
            return
        with lucchetto:
            sock.sendall(pacchetto)

    def _prossima_sequenza(self) -> int:
        with self._lock:
            self._sequenza_tm = (self._sequenza_tm + 1) % FINESTRA_SEQUENZA
            return self._sequenza_tm

    def _attiva_immagine(self, percorso: Path, dati: bytes, peer: str) -> None:
        giri = min(max(1, len(dati) // 4096), self.TETTO_ATTIVAZIONE)
        inizio = time.time()
        impronta = hashlib.sha256(dati)
        fatti = 0
        for _ in range(giri):
            impronta = hashlib.sha256(impronta.digest() + dati[:4096])
            fatti += 1
            if time.time() - inizio > self.TEMPO_MASSIMO_ATTIVAZIONE:
                break
        try:
            percorso.with_suffix(".impronta").write_text(impronta.hexdigest(),
                                                         encoding="utf-8")
        except OSError:
            pass
        self.bus.scrivi(BORDO_EVENTO, {
            "evento": "attivazione", "byte": len(dati), "giri": fatti,
            "durata_s": round(time.time() - inizio, 4), "peer": peer,
            "eseguito": False})

    def gestisci_pacchetto(self, grezzo: bytes, peer: str, sessione: str,
                           sock: socket.socket) -> None:
        try:
            tc = decodifica_comando(grezzo)
        except Exception:
            self.bus.scrivi(APP_COMANDO, {"peer": peer, "sessione": sessione,
                                          "comando": "illeggibile", "dimensione": len(grezzo),
                                          "esito": "errore"})
            return

        self.registro.identita.attivita(peer)
        salto = self.registro.nota_comando(peer, tc.sequenza)
        valido = self.catalogo.valido(tc.nome)
        esito = "accettato" if valido else "fuori-catalogo"
        extra: dict = {}

        if valido and tc.nome == "identita":
            dichiarata = tc.dati.decode("utf-8", "replace") or "?"
            nota = self.registro.dichiara(peer, dichiarata)
            extra = {"identita_cambiata": nota["cambiata"],
                     "identita_origini": nota["origini"]}
            if nota["cambiata"] or nota["origini"] > 1:
                self.bus.scrivi(BORDO_EVENTO, {
                    "evento": "identita", "peer": peer, "identita": nota["identita"],
                    "precedente": nota["precedente"], "origini": nota["origini"]})

        elif valido and tc.servizio == SERVIZIO_MEMORIA and self.archivio is not None:
            if tc.nome == "software":
                ok, nota_s, percorso = self.archivio.deposita_immagine(tc.dati)
                esito = "accettato" if ok else "rifiutato"
                self.bus.scrivi(BORDO_EVENTO, {
                    "evento": "scrittura", "byte": len(tc.dati), "esito": nota_s,
                    "immagine": True,
                    "libero_mb": round(self.archivio.libero_mb, 3), "peer": peer})
                if ok and percorso is not None:
                    self._attiva_immagine(percorso, tc.dati, peer)
            elif tc.nome == "verifica":
                da, quanti = area_richiesta(tc.dati)
                letti, impronta = self.archivio.verifica(da, quanti)
                self.bus.scrivi(BORDO_EVENTO, {
                    "evento": "verifica", "da": da, "chiesti": quanti,
                    "byte": letti, "impronta": impronta, "peer": peer})
                self._rapporto_verifica(sock, letti, impronta)
            else:
                ok, nota_s = self.archivio.scrivi(tc.dati)
                esito = "accettato" if ok else "rifiutato"
                self.bus.scrivi(BORDO_EVENTO, {
                    "evento": "scrittura", "byte": len(tc.dati), "esito": nota_s,
                    "libero_mb": round(self.archivio.libero_mb, 3), "peer": peer})

        dichiarata = self.registro.identita_di(peer)
        fuori = self.visibilita.fuori_visibilita(dichiarata, time.time())
        self.bus.scrivi(APP_COMANDO, {
            "peer": peer, "sessione": sessione, "comando": tc.nome,
            "servizio": tc.servizio, "sottotipo": tc.sottotipo,
            "sequenza": tc.sequenza, "dimensione": tc.dimensione,
            "salto_sequenza": salto, "esito": esito,
            "identita": dichiarata, "fuori_cono": fuori, **extra})

        if valido and tc.nome == "scarica":
            self._trasferisci(sock, chilobyte_richiesti(tc.dati))
        self._rispondi(sock, tc.nome)

    def _trasferisci(self, sock: socket.socket, kb: int) -> None:
        restano = kb * 1024
        try:
            while restano > 0:
                n = min(restano, BYTE_PER_PACCHETTO_DI_TRASFERIMENTO)
                self._invia(sock, codifica_telemetria(SERVIZIO_ARCHIVIO,
                                                      SOTTOTIPO_TRASFERIMENTO,
                                                      self._prossima_sequenza(),
                                                      bytes(n)))
                restano -= n
        except OSError:
            pass

    def _rapporto_verifica(self, sock: socket.socket, byte: int,
                           impronta: str) -> None:
        try:
            carico = byte.to_bytes(4, "big") + impronta.encode("ascii")[:16]
            self._invia(sock, codifica_telemetria(SERVIZIO_MEMORIA,
                                                  SOTTOTIPO_RAPPORTO_VERIFICA,
                                                  self._prossima_sequenza(),
                                                  carico))
        except OSError:
            pass

    def _rispondi(self, sock: socket.socket, nome: str) -> None:
        try:
            dati = b"\x01" if nome in self.catalogo.ammessi else b"\x00"
            self._invia(sock, codifica_telemetria(1, 7,
                                                  self._prossima_sequenza(), dati))
        except OSError:
            pass

    def imposta_allarme(self, stato: dict) -> None:
        self._stato_allarme = dict(stato)

    def _beacon(self) -> None:
        while True:
            time.sleep(self.periodo_beacon)
            sequenza = self._prossima_sequenza()
            libero = self.archivio.libero_mb if self.archivio else 0.0
            if self.stato_allarme_file:
                self._stato_allarme = leggi_stato_allarme(self.stato_allarme_file)
            carico = b"\x01" if self._stato_allarme.get("allarme") else b"\x00"
            pacchetto = codifica_telemetria(SERVIZIO_HOUSEKEEPING, 25, sequenza,
                                            carico + int(libero).to_bytes(4, "big"))
            with self._lock:
                destinatari = list(self._clients)
            for s in destinatari:
                try:
                    self._invia(s, pacchetto)
                except OSError:
                    continue

    def avvia(self) -> None:
        self._server = _Server(("0.0.0.0", self.porta), _Handler)
        self._server.servizio = self
        threading.Thread(target=self._beacon, daemon=True).start()
        self._server.serve_forever()

    def ferma(self) -> None:
        if self._server is not None:
            self._server.shutdown()


def main() -> None:
    ap = argparse.ArgumentParser(description="Servizio TC/TM del satellite")
    ap.add_argument("--vista", required=True, help="vista locale del satellite, JSON Lines")
    ap.add_argument("--porta", type=int, default=PORTA_PREDEFINITA, help="porta TCP del servizio")
    ap.add_argument("--archivio", default="/var/bordo", help="cartella dell'archivio di bordo")
    ap.add_argument("--limite-mb", type=float, default=64.0, help="capacità dell'archivio, MB")
    ap.add_argument("--stato-allarme", default=None,
                    help="file scritto dall'IDS, letto per il campo nel beacon")
    ap.add_argument("--visibilita", default=None,
                    help="calendario dei passaggi di bordo; assente per contatto continuo")
    args = ap.parse_args()

    bus = EventLog(args.vista)
    archivio = OnboardStorage(args.archivio, args.limite_mb)
    visibilita = Visibilita.da_file(args.visibilita)
    if args.visibilita:
        annuncia(bus, visibilita, Path(args.vista).stem)
    servizio = TelemetryCommandService(bus, args.porta, archivio,
                                       stato_allarme=args.stato_allarme,
                                       visibilita=visibilita)
    try:
        servizio.avvia()
    except KeyboardInterrupt:
        servizio.ferma()
    finally:
        bus.chiudi()


if __name__ == "__main__":
    main()
