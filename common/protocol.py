from __future__ import annotations

import warnings
from dataclasses import dataclass
from typing import Final

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from spacepackets.ecss.tc import PusTelecommand
    from spacepackets.ecss.tm import PusTelemetry

APID: Final[int] = 0x01

SERVIZIO_TEST: Final[int] = 17
SERVIZIO_HOUSEKEEPING: Final[int] = 3
SERVIZIO_FUNZIONE: Final[int] = 8
SERVIZIO_MEMORIA: Final[int] = 6
SERVIZIO_ARCHIVIO: Final[int] = 15

CATALOGO: Final[dict[str, tuple[int, int]]] = {
    "test": (SERVIZIO_TEST, 1),
    "identita": (SERVIZIO_TEST, 3),
    "housekeeping": (SERVIZIO_HOUSEKEEPING, 27),
    "funzione": (SERVIZIO_FUNZIONE, 1),
    "memoria": (SERVIZIO_MEMORIA, 2),
    "software": (SERVIZIO_MEMORIA, 1),
    "verifica": (SERVIZIO_MEMORIA, 9),
    "scarica": (SERVIZIO_ARCHIVIO, 9),
}
PER_CODICE: Final[dict[tuple[int, int], str]] = {v: k for k, v in CATALOGO.items()}

SOTTOTIPO_TRASFERIMENTO: Final[int] = 10
BYTE_PER_PACCHETTO_DI_TRASFERIMENTO: Final[int] = 4000

TRASFERIMENTO_MASSIMO_KB: Final[int] = 8192

TEMPO_MASSIMO_TRASFERIMENTO: Final[float] = 180.0


def richiesta_di_trasferimento(kb: float) -> bytes:
    return max(0, min(int(kb), TRASFERIMENTO_MASSIMO_KB)).to_bytes(4, "big")


def chilobyte_richiesti(dati: bytes) -> int:
    if len(dati) < 4:
        return 0
    return min(int.from_bytes(dati[:4], "big"), TRASFERIMENTO_MASSIMO_KB)


def quote_di_trasferimento(kb: float) -> list[int]:
    kb_intero = max(0, int(kb))
    intere, resto = divmod(kb_intero, TRASFERIMENTO_MASSIMO_KB)
    quote = [TRASFERIMENTO_MASSIMO_KB] * intere
    if resto:
        quote.append(resto)
    return quote


SOTTOTIPO_RAPPORTO_VERIFICA: Final[int] = 10
VERIFICA_MASSIMA_BYTE: Final[int] = 1 << 20

AREA_DI_VERIFICA_BYTE: Final[int] = 4096


def richiesta_di_verifica(da: int, quanti: int) -> bytes:
    return (max(0, da).to_bytes(4, "big")
            + max(0, min(quanti, VERIFICA_MASSIMA_BYTE)).to_bytes(4, "big"))


def area_richiesta(dati: bytes) -> tuple[int, int]:
    if len(dati) < 8:
        return 0, 0
    return (int.from_bytes(dati[:4], "big"),
            min(int.from_bytes(dati[4:8], "big"), VERIFICA_MASSIMA_BYTE))

LUNGHEZZA_INTESTAZIONE: Final[int] = 6

IDENT_COMANDO: Final[int] = 0x1800 | APID
IDENT_TELEMETRIA: Final[int] = 0x0800 | APID
IDENTIFICATORI_NOTI: Final[frozenset[int]] = frozenset(
    {IDENT_COMANDO, IDENT_TELEMETRIA})


@dataclass(frozen=True)
class Comando:
    nome: str
    servizio: int
    sottotipo: int
    sequenza: int
    dati: bytes

    @property
    def dimensione(self) -> int:
        return len(self.dati)


def lunghezza_totale(intestazione: bytes) -> int:
    if len(intestazione) < LUNGHEZZA_INTESTAZIONE:
        raise ValueError("intestazione incompleta")
    campo = int.from_bytes(intestazione[4:6], "big")
    return LUNGHEZZA_INTESTAZIONE + campo + 1


def codifica_grezzo(servizio: int, sottotipo: int, sequenza: int,
                    dati: bytes = b"") -> bytes:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        tc = PusTelecommand(service=servizio, message_subtype=sottotipo, apid=APID,
                            seq_count=sequenza & 0x3FFF, app_data=dati)
        return tc.pack()


def codifica_comando(nome: str, sequenza: int, dati: bytes = b"") -> bytes:
    if nome not in CATALOGO:
        raise KeyError(f"comando non nel catalogo: {nome}")
    servizio, sottotipo = CATALOGO[nome]
    return codifica_grezzo(servizio, sottotipo, sequenza, dati)


def decodifica_comando(grezzo: bytes) -> Comando:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        tc = PusTelecommand.unpack(grezzo)
        servizio = int(tc.service)
        sottotipo = int(tc.message_subtype)
        nome = PER_CODICE.get((servizio, sottotipo), "sconosciuto")
        return Comando(nome=nome, servizio=servizio, sottotipo=sottotipo,
                           sequenza=int(tc.seq_count), dati=bytes(tc.app_data or b""))


def codifica_telemetria(servizio: int, sottotipo: int, sequenza: int,
                        dati: bytes = b"") -> bytes:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        tm = PusTelemetry(service=servizio, message_subtype=sottotipo, apid=APID,
                          seq_count=sequenza & 0x3FFF, source_data=dati)
        return tm.pack()


def decodifica_telemetria(grezzo: bytes) -> tuple[int, int, int, bytes]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        tm = PusTelemetry.unpack(data=grezzo, timestamp_len=0)
        return (int(tm.service), int(tm.message_subtype), int(tm.seq_count),
                bytes(tm.tm_data or b""))


class Riassemblatore:
    def __init__(self, limite_byte: int = 1 << 20,
                 identificatori: frozenset[int] | None = None) -> None:
        self._buf = bytearray()
        self._limite = limite_byte
        self._identificatori = identificatori
        self._in_risincronizzazione = False
        self.risincronizzazioni = 0
        self.byte_scartati = 0

    def _sincronizza(self) -> bool:
        if self._identificatori is None:
            return True
        while len(self._buf) >= 2:
            ident = (self._buf[0] << 8) | self._buf[1]
            if ident in self._identificatori:
                return True
            if not self._in_risincronizzazione:
                self._in_risincronizzazione = True
                self.risincronizzazioni += 1
            del self._buf[0]
            self.byte_scartati += 1
        return False

    def alimenta(self, pezzo: bytes) -> list[bytes]:
        self._buf.extend(pezzo)
        if len(self._buf) > self._limite:
            self._buf.clear()
            return []
        completi: list[bytes] = []
        while True:
            if not self._sincronizza():
                break
            if len(self._buf) < LUNGHEZZA_INTESTAZIONE:
                break
            try:
                totale = lunghezza_totale(bytes(self._buf[:LUNGHEZZA_INTESTAZIONE]))
            except ValueError:
                break
            if totale <= 0:
                del self._buf[0]
                continue
            if len(self._buf) < totale:
                break
            completi.append(bytes(self._buf[:totale]))
            del self._buf[:totale]
            self._in_risincronizzazione = False
        return completi

    @property
    def in_attesa(self) -> int:
        return len(self._buf)
