from __future__ import annotations

import threading
import time

LUNGHEZZA_MASSIMA = 64

FINESTRA_ATTIVITA = 120.0


class RegistroIdentita:
    def __init__(self, finestra: float = FINESTRA_ATTIVITA) -> None:
        self._di_chi: dict[str, str] = {}
        self._origini: dict[str, set[str]] = {}
        self._visto: dict[str, float] = {}
        self.finestra = finestra
        self._lock = threading.Lock()

    def attivita(self, origine: str, adesso: float | None = None) -> None:
        with self._lock:
            self._visto[origine] = adesso if adesso is not None else time.time()

    def _attive(self, origini: set[str], adesso: float) -> int:
        return sum(1 for o in origini
                   if adesso - self._visto.get(o, 0.0) <= self.finestra)

    def dichiara(self, origine: str, identita: str,
                 adesso: float | None = None) -> dict:
        identita = (identita or "?").strip()[:LUNGHEZZA_MASSIMA] or "?"
        adesso = adesso if adesso is not None else time.time()
        with self._lock:
            self._visto[origine] = adesso
            precedente = self._di_chi.get(origine)
            cambiata = precedente is not None and precedente != identita
            if cambiata:
                vecchie = self._origini.get(precedente)
                if vecchie is not None:
                    vecchie.discard(origine)
            self._di_chi[origine] = identita
            origini = self._origini.setdefault(identita, set())
            origini.add(origine)
            return {"identita": identita, "cambiata": cambiata,
                    "origini": self._attive(origini, adesso),
                    "origini_mai": len(origini), "precedente": precedente}

    def di(self, origine: str) -> str | None:
        with self._lock:
            return self._di_chi.get(origine)

    def origini(self, identita: str | None, adesso: float | None = None) -> int:
        if not identita:
            return 0
        adesso = adesso if adesso is not None else time.time()
        with self._lock:
            return self._attive(self._origini.get(identita, set()), adesso)

    def condivise(self, adesso: float | None = None) -> list[str]:
        adesso = adesso if adesso is not None else time.time()
        with self._lock:
            return sorted(k for k, v in self._origini.items()
                          if self._attive(v, adesso) > 1)
