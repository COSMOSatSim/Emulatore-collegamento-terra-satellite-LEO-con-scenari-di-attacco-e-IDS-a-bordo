from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

RETE_SOCKET = "rete.socket"
RETE_AGGREGATO = "rete.aggregato"
BORDO_RISORSE = "bordo.risorse"
BORDO_EVENTO = "bordo.evento"
APP_COMANDO = "app.comando"
APP_SESSIONE = "app.sessione"

FINESTRA_SEQUENZA = 0x4000

NODO_VISIBILITA = "nodo.visibilita"
NODO_STATO = "nodo.stato"
NODO_ATTACCO = "nodo.attacco"
NODO_CANALE = "nodo.canale"

FAMIGLIA = {
    RETE_SOCKET: "rete",
    RETE_AGGREGATO: "rete",
    BORDO_RISORSE: "stato_di_bordo",
    BORDO_EVENTO: "stato_di_bordo",
    APP_COMANDO: "applicazione",
    APP_SESSIONE: "applicazione",
    NODO_VISIBILITA: "nodo",
    NODO_STATO: "nodo",
    NODO_ATTACCO: "nodo",
    NODO_CANALE: "nodo",
}


@dataclass(frozen=True)
class Event:
    t: float
    tipo: str
    dati: dict[str, Any]

    @property
    def famiglia(self) -> str:
        if self.tipo not in FAMIGLIA and self.tipo.startswith("nodo."):
            return "nodo"
        return FAMIGLIA.get(self.tipo, "rete")

    def come_riga(self) -> str:
        return json.dumps({"t": round(self.t, 6), "tipo": self.tipo, "dati": self.dati},
                          ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def da_riga(riga: str) -> "Event | None":
        riga = riga.strip()
        if not riga:
            return None
        try:
            d = json.loads(riga)
            return Event(t=float(d["t"]), tipo=str(d["tipo"]), dati=dict(d.get("dati", {})))
        except (ValueError, KeyError, TypeError):
            return None


class EventLog:
    def __init__(self, percorso: str | Path, flush_ogni: int = 1) -> None:
        self.percorso = Path(percorso)
        self.percorso.parent.mkdir(parents=True, exist_ok=True)
        self._f = self.percorso.open("a", encoding="utf-8")
        self._da_flush = 0
        self._flush_ogni = flush_ogni

    def scrivi(self, tipo: str, dati: dict[str, Any], t: float | None = None) -> Event:
        ev = Event(t=t if t is not None else time.time(), tipo=tipo, dati=dati)
        self._f.write(ev.come_riga() + "\n")
        self._da_flush += 1
        if self._da_flush >= self._flush_ogni:
            self._f.flush()
            self._da_flush = 0
        return ev

    def chiudi(self) -> None:
        try:
            self._f.flush()
        finally:
            self._f.close()

    def __enter__(self) -> "EventLog":
        return self

    def __exit__(self, *_: Any) -> None:
        self.chiudi()


def leggi_tutto(percorso: str | Path) -> list[Event]:
    out: list[Event] = []
    p = Path(percorso)
    if not p.exists():
        compressa = p.with_suffix(p.suffix + ".gz")
        if compressa.exists():
            p = compressa
        else:
            return out
    if p.suffix == ".gz":
        import gzip
        with gzip.open(p, "rt", encoding="utf-8", errors="replace") as f:
            testo = f.read()
    else:
        testo = p.read_text(encoding="utf-8", errors="replace")
    for riga in testo.splitlines():
        ev = Event.da_riga(riga)
        if ev is not None:
            out.append(ev)
    return out


class EventTail:
    def __init__(self, percorso: str | Path, dall_inizio: bool = True) -> None:
        self.percorso = Path(percorso)
        self._pos = 0
        self._resto = ""
        if not dall_inizio and self.percorso.exists():
            self._pos = self.percorso.stat().st_size

    def nuovi(self) -> Iterator[Event]:
        if not self.percorso.exists():
            return
        if self.percorso.suffix == ".gz":
            if self._pos == 0:
                self._pos = -1
                yield from leggi_tutto(self.percorso)
            return
        with self.percorso.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(self._pos)
            blocco = f.read()
            self._pos = f.tell()
        if not blocco:
            return
        blocco = self._resto + blocco
        righe = blocco.split("\n")
        self._resto = righe.pop()
        for riga in righe:
            ev = Event.da_riga(riga)
            if ev is not None:
                yield ev
