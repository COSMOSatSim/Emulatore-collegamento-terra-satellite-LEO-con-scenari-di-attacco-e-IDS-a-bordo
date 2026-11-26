from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Iterator

from model.config import CO_RESIDENTE, CapabilityDescriptor
from model.events import Event, EventTail


class CapturePoint(ABC):
    @property
    @abstractmethod
    def capacita(self) -> CapabilityDescriptor:
        ...

    @property
    @abstractmethod
    def nome(self) -> str:
        ...

    @abstractmethod
    def nuovi(self) -> Iterator[Event]:
        ...

    def _ammesso(self, ev: Event) -> bool:
        c = self.capacita
        return {"rete": c.rete, "applicazione": c.applicazione,
                "stato_di_bordo": c.stato_di_bordo}.get(ev.famiglia, False)


class OnboardCapturePoint(CapturePoint):
    def __init__(self, vista: str | Path, dall_inizio: bool = True) -> None:
        self._tail = EventTail(vista, dall_inizio=dall_inizio)

    @property
    def capacita(self) -> CapabilityDescriptor:
        return CapabilityDescriptor(rete=True, applicazione=True, stato_di_bordo=True)

    @property
    def nome(self) -> str:
        return CO_RESIDENTE

    def nuovi(self) -> Iterator[Event]:
        for ev in self._tail.nuovi():
            if self._ammesso(ev):
                yield ev


class ListCapturePoint(CapturePoint):
    def __init__(self, eventi: list[Event], capacita: CapabilityDescriptor | None = None,
                 nome: str = "lista") -> None:
        self._eventi = list(eventi)
        self._cap = capacita or CapabilityDescriptor()
        self._nome = nome

    @property
    def capacita(self) -> CapabilityDescriptor:
        return self._cap

    @property
    def nome(self) -> str:
        return self._nome

    def nuovi(self) -> Iterator[Event]:
        da_dare, self._eventi = self._eventi, []
        for ev in da_dare:
            if self._ammesso(ev):
                yield ev


def crea_punto_di_cattura(tipo: str, vista: str | Path, **kw: Any) -> CapturePoint:
    if tipo == CO_RESIDENTE:
        return OnboardCapturePoint(vista, **kw)
    raise ValueError(
        f"punto di cattura non disponibile: {tipo}; ammesso solo {CO_RESIDENTE}")
