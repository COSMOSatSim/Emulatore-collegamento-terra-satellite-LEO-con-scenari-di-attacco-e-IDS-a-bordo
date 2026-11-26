from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass
from typing import Iterator


ETH_IPV4 = 0x0800
IP_TCP = 6

FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04


@dataclass(frozen=True)
class Segmento:
    ip_mittente: str
    ip_destinatario: str
    porta_mittente: int
    porta_destinatario: int
    flag: int
    carico: bytes
    seq: int = 0

    @property
    def syn(self) -> bool:
        return bool(self.flag & FLAG_SYN)

    @property
    def chiude(self) -> bool:
        return bool(self.flag & (FLAG_FIN | FLAG_RST))

    @property
    def flusso(self) -> str:
        return (f"{self.ip_mittente}:{self.porta_mittente}>"
                f"{self.ip_destinatario}:{self.porta_destinatario}")


def analizza_telaio(telaio: bytes) -> Segmento | None:
    if len(telaio) < 14:
        return None
    if struct.unpack_from("!H", telaio, 12)[0] != ETH_IPV4:
        return None

    ip = telaio[14:]
    if len(ip) < 20:
        return None
    primo = ip[0]
    if primo >> 4 != 4:
        return None
    lunghezza_ip = (primo & 0x0F) * 4
    if lunghezza_ip < 20 or len(ip) < lunghezza_ip:
        return None
    if ip[9] != IP_TCP:
        return None
    totale = struct.unpack_from("!H", ip, 2)[0]
    if 0 < totale <= len(ip):
        ip = ip[:totale]
    mittente = ".".join(str(b) for b in ip[12:16])
    destinatario = ".".join(str(b) for b in ip[16:20])

    tcp = ip[lunghezza_ip:]
    if len(tcp) < 20:
        return None
    porta_m, porta_d = struct.unpack_from("!HH", tcp, 0)
    lunghezza_tcp = (tcp[12] >> 4) * 4
    if lunghezza_tcp < 20 or len(tcp) < lunghezza_tcp:
        return None
    flag = tcp[13]
    seq = struct.unpack_from("!I", tcp, 4)[0]
    return Segmento(mittente, destinatario, porta_m, porta_d, flag,
                    bytes(tcp[lunghezza_tcp:]), seq)


MODULO_TCP = 1 << 32


class OrdineTcp:
    ATTESA_MASSIMA_S = 3.0

    def __init__(self) -> None:
        self.prossimo: int | None = None
        self._attesa: dict[int, tuple[bytes, float]] = {}
        self.duplicati = 0
        self.fuori_ordine = 0
        self.buchi = 0

    def syn(self, seq: int) -> None:
        self.prossimo = (seq + 1) % MODULO_TCP
        self._attesa.clear()

    def _distanza(self, seq: int) -> int:
        assert self.prossimo is not None
        d = (seq - self.prossimo) % MODULO_TCP
        return d - MODULO_TCP if d >= MODULO_TCP // 2 else d

    def alimenta(self, seq: int, dati: bytes, t: float = 0.0) -> bytes:
        if not dati:
            return b""
        if self.prossimo is None:
            self.prossimo = seq
        d = self._distanza(seq)
        if d + len(dati) <= 0:
            self.duplicati += 1
            return self._scadute(t)
        if d > 0:
            self.fuori_ordine += 1
            vecchio = self._attesa.get(seq)
            if vecchio is None or len(vecchio[0]) < len(dati):
                self._attesa[seq] = (dati, t)
            return self._scadute(t)
        uscita = bytearray(dati[-d:] if d < 0 else dati)
        self.prossimo = (seq + len(dati)) % MODULO_TCP
        uscita += self._svuota()
        return bytes(uscita)

    def _svuota(self) -> bytes:
        uscita = bytearray()
        avanzato = True
        while avanzato and self._attesa:
            avanzato = False
            for seq in sorted(self._attesa, key=self._distanza):
                d = self._distanza(seq)
                if d > 0:
                    break
                dati, _ = self._attesa.pop(seq)
                if d + len(dati) > 0:
                    uscita += dati[-d:] if d < 0 else dati
                    self.prossimo = (seq + len(dati)) % MODULO_TCP
                avanzato = True
                break
        return bytes(uscita)

    def _scadute(self, t: float) -> bytes:
        if not self._attesa or not t:
            return b""
        if min(arrivo for _, arrivo in self._attesa.values()) > t - self.ATTESA_MASSIMA_S:
            return b""
        self.buchi += 1
        self.prossimo = min(self._attesa, key=self._distanza)
        return self._svuota()


def cattura_promiscua(interfaccia: str, dimensione: int = 65535,
                      secondi: float | None = None) -> Iterator[bytes]:
    if not hasattr(socket, "AF_PACKET"):
        raise RuntimeError("cattura sul filo disponibile solo su Linux")
    presa = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.htons(0x0003))
    presa.bind((interfaccia, 0))
    scadenza = None if secondi is None else time.time() + secondi
    try:
        while True:
            if scadenza is not None:
                rimasto = scadenza - time.time()
                if rimasto <= 0:
                    return
                presa.settimeout(rimasto)
            try:
                telaio, _ = presa.recvfrom(dimensione)
            except (socket.timeout, OSError):
                return
            yield telaio
    finally:
        presa.close()
