from __future__ import annotations

import argparse
import signal
import time
from pathlib import Path

from model.events import (APP_SESSIONE, BORDO_RISORSE, EventLog, RETE_AGGREGATO,
                          RETE_SOCKET)
from sensor.readers import LettoreBordo, leggi_contatori_rete, leggi_ss

PERIODO_PREDEFINITO = 0.5


class LocalSensor:
    def __init__(self, vista: str | Path, periodo: float = PERIODO_PREDEFINITO,
                 con_bordo: bool = True, radice_disco: str = "/",
                 archivio: str | None = None,
                 capacita_archivio_mb: float | None = None) -> None:
        self.log = EventLog(vista)
        self.periodo = periodo
        self.con_bordo = con_bordo
        self._bordo = (LettoreBordo(radice_disco, archivio=archivio,
                                    capacita_archivio_mb=capacita_archivio_mb)
                       if con_bordo else None)
        self._attivo = True
        self._visti: dict[str, float] = {}

    def ferma(self, *_: object) -> None:
        self._attivo = False

    def giro(self) -> int:
        adesso = time.time()
        scritti = 0

        socket_vivi = leggi_ss()
        chiavi_ora: set[str] = set()
        for s in socket_vivi:
            chiave = f"{s.locale}>{s.remoto}"
            chiavi_ora.add(chiave)
            if chiave not in self._visti:
                self._visti[chiave] = adesso
                self.log.scrivi(APP_SESSIONE,
                                {"evento": "apertura", "sessione": chiave,
                                 "peer": s.peer_ip, "congestione": s.congestione},
                                t=adesso)
                scritti += 1
            dati = s.come_dict()
            dati["sessione"] = chiave
            dati["peer"] = s.peer_ip
            dati["durata_s"] = round(adesso - self._visti[chiave], 3)
            self.log.scrivi(RETE_SOCKET, dati, t=adesso)
            scritti += 1

        for chiave in list(self._visti):
            if chiave not in chiavi_ora:
                self.log.scrivi(APP_SESSIONE,
                                {"evento": "chiusura", "sessione": chiave,
                                 "durata_s": round(adesso - self._visti[chiave], 3)},
                                t=adesso)
                del self._visti[chiave]
                scritti += 1

        contatori = leggi_contatori_rete()
        if contatori:
            interessanti = {k: v for k, v in contatori.items()
                            if k.startswith("Tcp.") or "Retrans" in k or "Listen" in k}
            self.log.scrivi(RETE_AGGREGATO, interessanti, t=adesso)
            scritti += 1

        if self._bordo is not None:
            stato = self._bordo.leggi().come_dict()
            if stato:
                self.log.scrivi(BORDO_RISORSE, stato, t=adesso)
                scritti += 1

        return scritti

    def esegui(self, durata: float | None = None) -> None:
        inizio = time.time()
        while self._attivo:
            avvio_giro = time.time()
            self.giro()
            if durata is not None and time.time() - inizio >= durata:
                break
            resto = self.periodo - (time.time() - avvio_giro)
            if resto > 0:
                time.sleep(resto)
        self.log.chiudi()


def main() -> None:
    ap = argparse.ArgumentParser(description="Sensore locale di un nodo")
    ap.add_argument("--vista", required=True, help="file JSON Lines della vista locale")
    ap.add_argument("--periodo", type=float, default=PERIODO_PREDEFINITO,
                    help="intervallo fra 2 campionamenti, s")
    ap.add_argument("--senza-bordo", action="store_true",
                    help="non campionare lo stato di bordo (nodo osservatore)")
    ap.add_argument("--durata", type=float, default=None,
                    help="durata del campionamento, s; senza valore fino all'arresto")
    ap.add_argument("--archivio", default=None,
                    help="cartella dell'archivio di bordo, di cui misurare lo spazio")
    ap.add_argument("--capacita-archivio-mb", type=float, default=None,
                    help="capacità dell'archivio, MB, riferimento dello spazio libero")
    args = ap.parse_args()

    sensore = LocalSensor(args.vista, args.periodo, con_bordo=not args.senza_bordo,
                          archivio=args.archivio,
                          capacita_archivio_mb=args.capacita_archivio_mb)
    signal.signal(signal.SIGTERM, sensore.ferma)
    signal.signal(signal.SIGINT, sensore.ferma)
    sensore.esegui(args.durata)


if __name__ == "__main__":
    main()
