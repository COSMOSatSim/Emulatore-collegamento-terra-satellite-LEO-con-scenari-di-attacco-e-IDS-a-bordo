from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

MARGINE_GUARDIA = 1.0


@dataclass(frozen=True)
class Finestra:
    inizio: float
    fine: float

    def contiene(self, t: float, margine: float = 0.0) -> bool:
        return self.inizio - margine <= t <= self.fine + margine


class Visibilita:
    INTERVALLO_RICARICA = 1.0

    def __init__(self, finestre: dict[str, tuple[Finestra, ...]] | None = None,
                 margine: float = MARGINE_GUARDIA,
                 sorgente: str | Path | None = None) -> None:
        self._finestre: dict[str, tuple[Finestra, ...]] = {
            str(k): tuple(v) for k, v in (finestre or {}).items() if v}
        self.margine = float(margine)
        self._sorgente = Path(sorgente) if sorgente and not self._finestre else None
        self._prossimo_controllo = 0.0
        self._al_caricamento: list[Callable[["Visibilita"], None]] = []

    def _forse_carica(self) -> None:
        if self._sorgente is None:
            return
        adesso = time.monotonic()
        if adesso < self._prossimo_controllo:
            return
        self._prossimo_controllo = adesso + self.INTERVALLO_RICARICA
        letta = Visibilita._leggi(self._sorgente)
        if letta is None or not letta._finestre:
            return
        self._finestre, self.margine = letta._finestre, letta.margine
        self._sorgente = None
        for avvisa in self._al_caricamento:
            avvisa(self)

    def al_caricamento(self, avvisa: Callable[["Visibilita"], None]) -> None:
        if self._finestre:
            avvisa(self)
        elif self._sorgente is not None:
            self._al_caricamento.append(avvisa)

    @property
    def in_attesa(self) -> bool:
        self._forse_carica()
        return self._sorgente is not None

    @property
    def dichiarata(self) -> bool:
        self._forse_carica()
        return bool(self._finestre)

    def conosce(self, stazione: str | None) -> bool:
        self._forse_carica()
        return bool(stazione) and str(stazione) in self._finestre

    def finestre_di(self, stazione: str | None) -> tuple[Finestra, ...]:
        self._forse_carica()
        return self._finestre.get(str(stazione), ()) if stazione else ()

    def in_visibilita(self, stazione: str | None, t: float) -> bool:
        if not self.conosce(stazione):
            return True
        return any(f.contiene(t, self.margine) for f in self.finestre_di(stazione))

    def fuori_visibilita(self, stazione: str | None, t: float) -> bool:
        if not self.conosce(stazione):
            return False
        return not any(f.contiene(t, self.margine)
                       for f in self.finestre_di(stazione))

    def fine_finestra(self, stazione: str | None, t: float) -> float | None:
        for f in self.finestre_di(stazione):
            if f.contiene(t, self.margine):
                return f.fine
        return None

    def prossima_apertura(self, stazione: str | None, t: float) -> float | None:
        successive = [f.inizio for f in self.finestre_di(stazione) if f.inizio > t]
        return min(successive) if successive else None

    def stazioni(self) -> list[str]:
        self._forse_carica()
        return sorted(self._finestre)

    def come_dict(self) -> dict[str, Any]:
        self._forse_carica()
        return {"margine_s": self.margine,
                "finestre": {s: [[f.inizio, f.fine] for f in fs]
                             for s, fs in sorted(self._finestre.items())}}

    @staticmethod
    def da_dict(d: dict[str, Any] | None) -> "Visibilita":
        if not d:
            return Visibilita()
        grezze = d.get("finestre", d) or {}
        finestre: dict[str, tuple[Finestra, ...]] = {}
        for stazione, intervalli in grezze.items():
            raccolte = []
            for coppia in intervalli or ():
                try:
                    a, b = float(coppia[0]), float(coppia[1])
                except (TypeError, ValueError, IndexError):
                    continue
                if b > a:
                    raccolte.append(Finestra(a, b))
            if raccolte:
                finestre[str(stazione)] = tuple(sorted(raccolte,
                                                       key=lambda f: f.inizio))
        return Visibilita(finestre, float(d.get("margine_s", MARGINE_GUARDIA)))

    @staticmethod
    def _leggi(percorso: Path) -> "Visibilita | None":
        try:
            return Visibilita.da_dict(json.loads(percorso.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError):
            return None

    @staticmethod
    def da_file(percorso: str | Path | None) -> "Visibilita":
        if not percorso:
            return Visibilita()
        letta = Visibilita._leggi(Path(percorso))
        if letta is not None and letta._finestre:
            return letta
        return Visibilita(sorgente=percorso)


def annuncia(bus: Any, visibilita: Visibilita, nodo: str) -> None:
    from model.events import NODO_VISIBILITA

    avviato = time.time()

    def scrivi(v: Visibilita) -> None:
        bus.scrivi(NODO_VISIBILITA, {
            "nodo": nodo, "stazioni": v.stazioni(),
            "finestre": sum(len(v.finestre_di(s)) for s in v.stazioni()),
            "caricato_dopo_s": round(time.time() - avviato, 3)})

    visibilita.al_caricamento(scrivi)


def risolvi(dichiarate: dict[str, Iterable[Iterable[float]]] | None,
            inizio: float, margine: float = MARGINE_GUARDIA) -> dict[str, Any]:
    fuori: dict[str, list[list[float]]] = {}
    for stazione, intervalli in (dichiarate or {}).items():
        raccolte = []
        for coppia in intervalli or ():
            try:
                a, b = float(coppia[0]), float(coppia[1])
            except (TypeError, ValueError, IndexError):
                continue
            if b > a:
                raccolte.append([inizio + a, inizio + b])
        if raccolte:
            fuori[str(stazione)] = sorted(raccolte, key=lambda c: c[0])
    return {"margine_s": float(margine), "finestre": fuori}
