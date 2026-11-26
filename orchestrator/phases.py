from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

ORDINE = ("avvio", "nominale", "quiete", "attacco", "osservazione", "arresto")


@dataclass(frozen=True)
class Fase:
    nome: str
    durata: float
    inizio: float
    fine: float


class GroundTruthRecorder:
    def __init__(self, percorso: str | Path) -> None:
        self.percorso = Path(percorso)
        self.percorso.parent.mkdir(parents=True, exist_ok=True)
        self._f = self.percorso.open("a", encoding="utf-8")

    def _riga(self, etichetta: str, dati: dict[str, Any], t: float | None = None) -> None:
        voce = {"t": round(t if t is not None else time.time(), 6),
                "etichetta": etichetta, "dati": dati}
        self._f.write(json.dumps(voce, ensure_ascii=False, separators=(",", ":")) + "\n")
        self._f.flush()

    def configurazione(self, conf: dict[str, Any]) -> None:
        self._riga("configurazione", conf)

    def fase(self, nome: str, evento: str, t: float | None = None) -> None:
        self._riga("fase", {"nome": nome, "evento": evento}, t)

    def attacco(self, evento: str, classe: str, ramo: str, conoscenza: str,
                t: float | None = None) -> None:
        self._riga("attacco", {"evento": evento, "classe": classe, "ramo": ramo,
                               "conoscenza": conoscenza}, t)

    def ricognizione(self, evento: str, t: float | None = None) -> None:
        self._riga("ricognizione", {"evento": evento}, t)

    def evento(self, descrizione: str, t: float | None = None) -> None:
        self._riga("evento", {"descrizione": descrizione}, t)

    def chiudi(self) -> None:
        if self._f.closed:
            return
        try:
            self._f.flush()
        finally:
            self._f.close()


class PhaseScheduler:
    def __init__(self, durate: dict[str, int], t0: float | None = None) -> None:
        self.durate = {k: float(durate.get(k, 0)) for k in ORDINE}
        self.t0 = t0 if t0 is not None else time.time()
        self._fasi = self._calcola()

    def _calcola(self) -> list[Fase]:
        fasi: list[Fase] = []
        t = self.t0
        for nome in ORDINE:
            d = self.durate.get(nome, 0.0)
            if d <= 0:
                continue
            fasi.append(Fase(nome=nome, durata=d, inizio=t, fine=t + d))
            t += d
        return fasi

    @property
    def fasi(self) -> list[Fase]:
        return list(self._fasi)

    def intervallo(self, nome: str) -> tuple[float, float] | None:
        for f in self._fasi:
            if f.nome == nome:
                return f.inizio, f.fine
        return None

    @property
    def durata_totale(self) -> float:
        return sum(f.durata for f in self._fasi)

    def finestra_attacco(self) -> tuple[float, float] | None:
        for f in self._fasi:
            if f.nome == "attacco":
                return (f.inizio, f.fine)
        return None

    def fase_a(self, t: float) -> str | None:
        for f in self._fasi:
            if f.inizio <= t < f.fine:
                return f.nome
        return None

    def scorri(self, dormi: Callable[[float], None] = time.sleep,
               adesso: Callable[[], float] = time.time) -> Iterator[Fase]:
        for f in self._fasi:
            yield f
            resto = f.fine - adesso()
            if resto > 0:
                dormi(resto)
