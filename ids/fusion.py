from __future__ import annotations

import re
from dataclasses import dataclass, field

from ids.detectors import DetectorScore

PESI_PREDEFINITI = {
    "volumetrico": 1.0,
    "coerenza-identita": 1.2,
    "grammatica": 1.2,
    "deviazione-bordo": 1.0,
}

ENTITA_GLOBALE = "globale"

SOGLIE_RIVELATORE: dict[str, float] = {}

_INDIRIZZO = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):")


def entita_di(chiave: str) -> str:
    m = _INDIRIZZO.match(chiave)
    return m.group(1) if m else ENTITA_GLOBALE


SOGLIA = 0.95

MASSIMI_SEGNALI = 8

SU = 2
GIU = 5


@dataclass
class Decisione:
    t: float
    punteggio: float
    in_allarme: bool
    appena_alzato: bool
    appena_abbassato: bool
    contributi: dict[str, float] = field(default_factory=dict)
    segnali: dict[str, float] = field(default_factory=dict)
    rivelatori_attivi: list[str] = field(default_factory=list)
    rivelatori_assenti: list[str] = field(default_factory=list)
    motivo: str = ""
    punteggi_per_entita: dict[str, float] = field(default_factory=dict)
    entita_in_allarme: tuple[str, ...] = ()
    entita_alzate: tuple[str, ...] = ()
    entita_abbassate: tuple[str, ...] = ()


class ScoreFusion:
    def __init__(self, pesi: dict[str, float] | None = None, soglia: float = SOGLIA,
                 su: int = SU, giu: int = GIU,
                 soglie_rivelatore: dict[str, float] | None = None) -> None:
        self.pesi = dict(pesi or PESI_PREDEFINITI)
        self.soglia = soglia
        self.soglie_rivelatore = dict(SOGLIE_RIVELATORE if soglie_rivelatore is None
                                      else soglie_rivelatore)
        self.su = su
        self.giu = giu
        self._sopra = 0
        self._sotto = 0
        self._in_allarme = False
        self._stato_entita: dict[str, list] = {}

    def _da_solo(self, punteggi: list[DetectorScore]) -> bool:
        for p in punteggi:
            soglia = self.soglie_rivelatore.get(p.nome)
            if soglia is not None and p.punteggio >= soglia:
                return True
        return False

    def combina(self, t: float, punteggi: list[DetectorScore],
                assenti: list[str] | None = None) -> Decisione:
        attivi = [p for p in punteggi if p.attivo]
        peso_massimo = max((self.pesi.get(p.nome, 1.0) for p in attivi), default=1.0) or 1.0
        prodotto = 1.0
        for p in attivi:
            k = self.pesi.get(p.nome, 1.0) / peso_massimo
            contributo = max(0.0, min(1.0, p.punteggio)) * k
            prodotto *= (1.0 - contributo)
        punteggio = 1.0 - prodotto

        if punteggio >= self.soglia or self._da_solo(attivi):
            self._sopra += 1
            self._sotto = 0
        else:
            self._sotto += 1
            self._sopra = 0

        alzato = abbassato = False
        if not self._in_allarme and self._sopra >= self.su:
            self._in_allarme, alzato = True, True
        elif self._in_allarme and self._sotto >= self.giu:
            self._in_allarme, abbassato = False, True

        per_entita: dict[str, float] = {}
        for chi in {entita_di(k) for p in attivi for k in p.contributi}:
            prodotto_suo = 1.0
            for p in attivi:
                suoi = [v for k, v in p.contributi.items() if entita_di(k) == chi]
                if not suoi:
                    continue
                k_peso = self.pesi.get(p.nome, 1.0) / peso_massimo
                prodotto_suo *= (1.0 - max(0.0, min(1.0, max(suoi))) * k_peso)
            per_entita[chi] = 1.0 - prodotto_suo

        alzate: list[str] = []
        abbassate: list[str] = []
        for chi, punteggio_suo in per_entita.items():
            st = self._stato_entita.setdefault(chi, [0, 0, False])
            suoi_da_soli = any(
                (s := self.soglie_rivelatore.get(p.nome)) is not None
                and max((v for k, v in p.contributi.items()
                         if entita_di(k) == chi), default=0.0) >= s
                for p in attivi)
            if punteggio_suo >= self.soglia or suoi_da_soli:
                st[0], st[1] = st[0] + 1, 0
            else:
                st[0], st[1] = 0, st[1] + 1
            if not st[2] and st[0] >= self.su:
                st[2] = True
                alzate.append(chi)
            elif st[2] and st[1] >= self.giu:
                st[2] = False
                abbassate.append(chi)
        for chi in [c for c in self._stato_entita if c not in per_entita]:
            st = self._stato_entita[chi]
            st[0], st[1] = 0, st[1] + 1
            if st[2] and st[1] >= self.giu:
                st[2] = False
                abbassate.append(chi)

        in_allarme = tuple(sorted(c for c, s in self._stato_entita.items() if s[2]))
        contributi = {p.nome: round(p.punteggio, 4) for p in attivi}
        tutti = [(f"{p.nome}/{k}", v) for p in attivi for k, v in p.contributi.items()]
        segnali = {k: round(v, 4)
                   for k, v in sorted(tutti, key=lambda kv: -kv[1])[:MASSIMI_SEGNALI]}
        motivo = ""
        if attivi:
            peggiore = max(attivi, key=lambda p: p.punteggio)
            motivo = peggiore.motivo or peggiore.principale
        return Decisione(t=t, punteggio=punteggio, in_allarme=self._in_allarme,
                         appena_alzato=alzato, appena_abbassato=abbassato,
                         contributi=contributi, segnali=segnali,
                         rivelatori_attivi=[p.nome for p in attivi],
                         rivelatori_assenti=list(assenti or []), motivo=motivo,
                         punteggi_per_entita={c: round(v, 4)
                                              for c, v in per_entita.items()},
                         entita_alzate=tuple(sorted(alzate)),
                         entita_abbassate=tuple(sorted(abbassate)),
                         entita_in_allarme=in_allarme)


class LimitatoreFrequenza:
    def __init__(self, intervallo_aggiornamento: float = 60.0) -> None:
        self.intervallo = intervallo_aggiornamento
        self._ultimo: float | None = None

    def consenti(self, d: Decisione) -> bool:
        if d.appena_alzato or d.appena_abbassato:
            self._ultimo = d.t
            return True
        if not d.in_allarme:
            return False
        if self._ultimo is None or d.t - self._ultimo >= self.intervallo:
            self._ultimo = d.t
            return True
        return False
