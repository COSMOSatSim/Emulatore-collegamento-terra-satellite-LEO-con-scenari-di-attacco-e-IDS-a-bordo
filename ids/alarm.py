from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ids.fusion import Decisione

LIVELLI = ("informazione", "attenzione", "allarme")


@dataclass
class Alarm:
    t: float
    livello: str
    punteggio: float
    motivo: str
    contributi: dict[str, float] = field(default_factory=dict)
    segnali: dict[str, float] = field(default_factory=dict)
    rivelatori_attivi: list[str] = field(default_factory=list)
    rivelatori_assenti: list[str] = field(default_factory=list)
    finestra: float = 0.0
    sessione: str | None = None
    tipo: str = "apertura"
    entita: str | None = None

    def come_dict(self) -> dict[str, Any]:
        return asdict(self)

    def come_riga(self) -> str:
        return json.dumps(self.come_dict(), ensure_ascii=False, separators=(",", ":"))


class AlarmSink(ABC):
    accetta_entita: bool = False

    @abstractmethod
    def emetti(self, a: Alarm) -> bool:
        pass


class LocalAlarmLog(AlarmSink):
    accetta_entita = True

    def __init__(self, percorso: str | Path) -> None:
        self.percorso = Path(percorso)
        self.percorso.parent.mkdir(parents=True, exist_ok=True)
        self._f = self.percorso.open("a", encoding="utf-8")

    def emetti(self, a: Alarm) -> bool:
        self._f.write(a.come_riga() + "\n")
        self._f.flush()
        return True

    def chiudi(self) -> None:
        try:
            self._f.flush()
        finally:
            self._f.close()


class DownlinkFlag(AlarmSink):
    def __init__(self, scrivi_stato: Callable[[dict[str, Any]], object]) -> None:
        self._scrivi = scrivi_stato
        self.falliti = 0

    def emetti(self, a: Alarm) -> bool:
        try:
            self._scrivi({"allarme": a.livello != "informazione",
                          "punteggio": round(a.punteggio, 3), "t": a.t})
            return True
        except Exception:
            self.falliti += 1
            return False


class StatoAllarmeSuFile(AlarmSink):
    def __init__(self, percorso: str | Path) -> None:
        self.percorso = Path(percorso)
        self.percorso.parent.mkdir(parents=True, exist_ok=True)
        self.falliti = 0

    def emetti(self, a: Alarm) -> bool:
        stato = {"allarme": a.tipo != "chiusura" and a.livello != "informazione",
                 "livello": a.livello, "punteggio": round(a.punteggio, 3),
                 "motivo": a.motivo, "t": a.t}
        try:
            temporaneo = self.percorso.with_suffix(".tmp")
            temporaneo.write_text(json.dumps(stato, ensure_ascii=False),
                                  encoding="utf-8")
            temporaneo.replace(self.percorso)
            return True
        except OSError:
            self.falliti += 1
            return False


def leggi_stato_allarme(percorso: str | Path) -> dict[str, Any]:
    try:
        return json.loads(Path(percorso).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"allarme": False, "punteggio": 0.0}


class AlarmEmitter:
    def __init__(self, sinks: list[AlarmSink]) -> None:
        self.sinks = list(sinks)
        self.emessi = 0

    def emetti(self, a: Alarm) -> int:
        partiti = 0
        for s in self.sinks:
            if a.entita is not None and not s.accetta_entita:
                continue
            if s.emetti(a):
                partiti += 1
        self.emessi += 1
        return partiti

    @staticmethod
    def da_decisione(d: Decisione, finestra: float = 0.0) -> Alarm:
        if d.appena_alzato:
            tipo, livello = "apertura", "allarme"
        elif d.appena_abbassato:
            tipo, livello = "chiusura", "informazione"
        else:
            tipo, livello = "aggiornamento", "attenzione"
        return Alarm(t=d.t, livello=livello, punteggio=d.punteggio, motivo=d.motivo,
                     contributi=d.contributi, segnali=d.segnali,
                     rivelatori_attivi=d.rivelatori_attivi,
                     rivelatori_assenti=d.rivelatori_assenti, finestra=finestra,
                     tipo=tipo)

    @staticmethod
    def da_entita(d: Decisione, entita: str, tipo: str, finestra: float = 0.0) -> Alarm:
        from ids.fusion import entita_di
        livello = "allarme" if tipo != "chiusura" else "informazione"
        suoi = {k: v for k, v in d.segnali.items()
                if entita_di(k.partition("/")[2]) == entita}
        return Alarm(t=d.t, livello=livello,
                     punteggio=d.punteggi_per_entita.get(entita, 0.0),
                     motivo=f"entità {entita}", contributi=d.contributi,
                     segnali=suoi, rivelatori_attivi=d.rivelatori_attivi,
                     rivelatori_assenti=d.rivelatori_assenti, finestra=finestra,
                     tipo=tipo, entita=entita)
