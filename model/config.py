from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict, replace
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

from common.andamento_rtt import FORME as ANDAMENTI_RTT
from common.riconfigurazione import CASUALE, FORMA_PREDEFINITA

BBR = "bbr"
BBR3 = "bbr3"
STANDARD = "cubic"

CO_RESIDENTE = "co-residente"


@dataclass(frozen=True)
class CapabilityDescriptor:
    rete: bool = True
    applicazione: bool = True
    stato_di_bordo: bool = True

    def soddisfa(self, richieste: frozenset[str]) -> bool:
        posseduta = {"rete": self.rete, "applicazione": self.applicazione,
                     "stato_di_bordo": self.stato_di_bordo}
        return all(posseduta.get(r, False) for r in richieste)

    def mancanti(self, richieste: frozenset[str]) -> set[str]:
        posseduta = {"rete": self.rete, "applicazione": self.applicazione,
                     "stato_di_bordo": self.stato_di_bordo}
        return {r for r in richieste if not posseduta.get(r, False)}


@dataclass(frozen=True)
class ChannelProfile:
    nome: str = "LEO"
    ritardo_ms: float = 20.0
    jitter_ms: float = 3.0
    perdita_pct: float = 0.3
    banda_mbit: float = 50.0
    strozzatura_salita_mbit: float | None = None
    riconfigurazione_s: float | None = None
    riconfigurazione_ritardo_max_ms: float = 0.0
    andamento_rtt: str | None = None
    ritardo_ai_bordi_ms: float = 0.0

    @property
    def varia_nella_finestra(self) -> bool:
        return self.riconfigurazione_s is None and \
            self.andamento_rtt in ANDAMENTI_RTT and \
            self.ritardo_ai_bordi_ms > self.ritardo_ms

    @property
    def forma_riconfigurazione(self) -> str | None:
        if not self.si_riconfigura:
            return None
        return self.andamento_rtt or FORMA_PREDEFINITA

    @property
    def si_riconfigura(self) -> bool:
        return bool(self.riconfigurazione_s) and \
            self.riconfigurazione_ritardo_max_ms > self.ritardo_ms

    @property
    def rtt_atteso_ms(self) -> float:
        return 2 * self.ritardo_ms

    @property
    def ritardo_massimo_ms(self) -> float:
        return self.riconfigurazione_ritardo_max_ms if self.si_riconfigura \
            else self.ritardo_ms

    @property
    def rtt_massimo_atteso_ms(self) -> float:
        return 2 * self.ritardo_massimo_ms

    RITARDO_DI_CODA_MASSIMO_S = 0.5

    def limite_coda_pacchetti(self, mtu_byte: int = 1500) -> int:
        bdp_byte = self.banda_mbit * 1e6 / 8 * (self.rtt_atteso_ms / 1000.0)
        tetto = int(self.banda_mbit * 1e6 / 8 * self.RITARDO_DI_CODA_MASSIMO_S / mtu_byte)
        return max(10, int(3 * bdp_byte / mtu_byte), min(1000, tetto))

    def con(self, **modifiche: Any) -> "ChannelProfile":
        sconosciute = set(modifiche) - set(self.__dataclass_fields__)
        if sconosciute:
            raise ValueError("voci di canale sconosciute: " + ", ".join(sorted(sconosciute)))
        return replace(self, **modifiche)

    def comandi_strozzatura(self, interfaccia: str = "eth0") -> list[str]:
        if not self.strozzatura_salita_mbit:
            return []
        return [
            f"tc qdisc replace dev {interfaccia} handle ffff: ingress",
            f"tc filter replace dev {interfaccia} parent ffff: protocol ip "
            f"prio 1 u32 match u32 0 0 "
            f"police rate {self.strozzatura_salita_mbit}mbit burst 64k drop "
            f"flowid :1",
        ]


@dataclass(frozen=True)
class TransportProfile:
    nome: str = "P-BBR"
    predefinito: str = BBR
    per_ruolo: dict[str, str] = field(default_factory=dict)

    @property
    def algoritmi(self) -> tuple[str, ...]:
        return tuple(sorted({self.predefinito, *self.per_ruolo.values()}))

    def algoritmo(self, ruolo: str) -> str:
        return self.per_ruolo.get(ruolo, self.predefinito)

    @staticmethod
    def profilo(nome: str) -> "TransportProfile":
        if nome in ("standard", "std", "P-STD", STANDARD):
            return TransportProfile(nome="P-STD", predefinito=STANDARD)
        if nome in ("bbr", "P-BBR", BBR):
            return TransportProfile(nome="P-BBR", predefinito=BBR)
        if nome in ("bbr3", "P-BBR3", BBR3):
            return TransportProfile(nome="P-BBR3", predefinito=BBR3)
        raise ValueError(f"profilo di trasporto sconosciuto: {nome}")


class Ruolo(StrEnum):
    SATELLITE = "satellite"
    GROUND = "ground"
    ATTACKER = "attacker"
    OBSERVER = "observer"


@dataclass(frozen=True)
class NodeSpec:
    nome: str
    ruolo: str
    immagine: str
    domini: tuple[str, ...] = ("RADIO",)
    indirizzo: str | None = None
    memoria: str | None = None
    cpu: float | None = None
    sysctl: tuple[str, ...] = ()


@dataclass(frozen=True)
class WorkloadProfile:
    comandi_al_minuto: float = 12.0
    variabilita: float = 0.25
    durata_sessione_s: float = 150.0
    variabilita_sessione: float = 0.4
    pausa_fra_sessioni_s: float = 25.0
    composizione: dict[str, float] = field(
        default_factory=lambda: {"test": 0.24, "housekeeping": 0.44, "funzione": 0.28,
                                 "memoria": 0.02, "identita": 0.02})
    telemetria_kb: float = 0.0
    telemetria_ogni_s: float = 60.0

    def con(self, **modifiche: Any) -> "WorkloadProfile":
        sconosciute = set(modifiche) - set(self.__dataclass_fields__)
        if sconosciute:
            raise ValueError("voci di carico sconosciute: " + ", ".join(sorted(sconosciute)))
        return replace(self, **modifiche)


@dataclass
class ScenarioSpec:
    id: str
    classe: str = "nessuna"
    ramo: str = "-"
    conoscenza: str = "-"
    pazienza: float = 1.0
    identita_dichiarata: str = "nessuna"
    identita_esplorazione: str = "segnaposto"
    imita: str = "aggregata"
    dimensione_comandi: str = "fissa-16"
    vittima: str = "prima-alfabetica"
    jitter: str = "no"
    forma_sessioni: str = "continua"
    distanza_raffiche_s: float = 1.5
    topologia: str = "variante-a"
    ground_unit: int = 2
    canale: ChannelProfile = field(default_factory=ChannelProfile)
    trasporto: TransportProfile = field(default_factory=TransportProfile)
    punto_di_cattura: str = CO_RESIDENTE
    fasi: dict[str, int] = field(default_factory=lambda: {
        "avvio": 120, "nominale": 900, "quiete": 120,
        "attacco": 480, "osservazione": 180, "arresto": 60})
    carico_nominale: WorkloadProfile = field(default_factory=WorkloadProfile)
    visibilita: dict[str, list[list[float]]] = field(default_factory=dict)
    attesi: list[str] = field(default_factory=list)
    carico_per_stazione: dict[str, dict[str, Any]] = field(default_factory=dict)
    canali_per_nodo: dict[str, dict[str, Any]] = field(default_factory=dict)
    seme: int | None = None
    identita_attaccante: str | None = None

    def carico_di(self, stazione: str) -> WorkloadProfile:
        return self.carico_nominale.con(**self.carico_per_stazione.get(stazione, {}))

    def canale_di(self, nodo: str) -> ChannelProfile:
        return self.canale.con(**self.canali_per_nodo.get(nodo, {}))

    def ritardo_massimo_di(self, nodo: str) -> float:
        if nodo == "satellite":
            return self.canale.ritardo_massimo_ms
        c = self.canale_di(nodo)
        if nodo in (self.visibilita or {}) and c.varia_nella_finestra:
            return max(c.ritardo_massimo_ms, c.ritardo_ai_bordi_ms)
        return c.ritardo_massimo_ms

    def _problemi_andamento(self, nome: str, c: ChannelProfile) -> list[str]:
        if c.riconfigurazione_s is not None:
            problemi = []
            if c.andamento_rtt not in (None, *ANDAMENTI_RTT, CASUALE):
                problemi.append(f"{nome}: andamento dell'RTT sconosciuto: {c.andamento_rtt}")
            if c.ritardo_ai_bordi_ms:
                problemi.append(f"{nome}: ritardo ai bordi non usato con la "
                                "riconfigurazione")
            return problemi
        if c.andamento_rtt is None:
            return []
        if c.andamento_rtt == CASUALE:
            return [f"{nome}: andamento '{CASUALE}' solo con la riconfigurazione"]
        if c.andamento_rtt not in ANDAMENTI_RTT:
            return [f"{nome}: andamento dell'RTT sconosciuto: {c.andamento_rtt}"]
        problemi = []
        if c.ritardo_ai_bordi_ms <= c.ritardo_ms:
            problemi.append(
                f"{nome}: ritardo ai bordi ({c.ritardo_ai_bordi_ms:g} ms) non "
                f"superiore al nominale ({c.ritardo_ms:g} ms)")
        if not self.visibilita:
            problemi.append(f"{nome}: andamento dell'RTT senza finestre di visibilità")
        return problemi

    @staticmethod
    def da_file(percorso: str | Path) -> "ScenarioSpec":
        dati = yaml.safe_load(Path(percorso).read_text(encoding="utf-8"))
        return ScenarioSpec.da_dict(dati)

    @staticmethod
    def da_dict(d: dict[str, Any]) -> "ScenarioSpec":
        canale = ChannelProfile(**d.get("canale", {}))
        trasporto = TransportProfile(**d.get("trasporto", {}))
        carico = WorkloadProfile(**d.get("carico_nominale", {}))
        noti = {"canale", "trasporto", "carico_nominale"}
        resto = {k: v for k, v in d.items() if k not in noti}
        return ScenarioSpec(canale=canale, trasporto=trasporto,
                            carico_nominale=carico, **resto)

    def valida(self) -> list[str]:
        problemi: list[str] = []
        if self.ground_unit < 1:
            problemi.append("nessuna ground unit legittima")
        if self.punto_di_cattura != CO_RESIDENTE:
            problemi.append(
                f"punto di cattura non disponibile: {self.punto_di_cattura}; "
                f"ammesso solo {CO_RESIDENTE}")
        if self.fasi.get("nominale", 0) < 300:
            problemi.append("fase nominale inferiore a 5 minuti: profilo instabile")
        if self.classe != "nessuna" and self.fasi.get("attacco", 0) <= 0:
            problemi.append("classe di attacco senza finestra d'attacco")
        if self.canale.perdita_pct < 0 or self.canale.perdita_pct > 100:
            problemi.append("perdita fuori intervallo")
        c = self.canale
        if c.riconfigurazione_s is not None:
            if c.riconfigurazione_s <= 0:
                problemi.append("durata del passaggio del satellite non positiva")
            if c.riconfigurazione_ritardo_max_ms <= c.ritardo_ms:
                problemi.append(
                    f"riconfigurazione con ritardo massimo "
                    f"({c.riconfigurazione_ritardo_max_ms:g} ms) non superiore al "
                    f"nominale ({c.ritardo_ms:g} ms)")
        problemi += self._problemi_andamento("canale", self.canale)
        strozzatura = self.canale.strozzatura_salita_mbit
        if strozzatura is not None and strozzatura >= self.canale.banda_mbit:
            problemi.append(
                f"strozzatura in salita ({strozzatura:g} Mbit) non inferiore "
                f"alla banda di un nodo ({self.canale.banda_mbit:g} Mbit)")
        for nome, voci in (self.carico_per_stazione or {}).items():
            try:
                self.carico_di(nome)
            except (ValueError, TypeError) as errore:
                problemi.append(f"carico di {nome}: {errore}")
        for nome, voci in (self.canali_per_nodo or {}).items():
            if nome == "satellite":
                problemi.append("canale del satellite non dichiarabile per nodo")
            try:
                c = self.canale_di(nome)
            except (ValueError, TypeError) as errore:
                problemi.append(f"canale di {nome}: {errore}")
                continue
            if c.ritardo_ms < 0 or c.banda_mbit <= 0:
                problemi.append(f"canale di {nome}: ritardo o banda non validi")
            if "andamento_rtt" in voci or "ritardo_ai_bordi_ms" in voci:
                problemi += self._problemi_andamento(f"canale di {nome}", c)
        for stazione, intervalli in (self.visibilita or {}).items():
            if not intervalli:
                problemi.append(f"{stazione}: visibilità dichiarata ma vuota")
            for coppia in intervalli or ():
                if len(coppia) != 2 or coppia[1] <= coppia[0]:
                    problemi.append(f"{stazione}: finestra di visibilità non valida")
        return problemi


@dataclass(frozen=True)
class RunConfig:
    run_id: str
    scenario_id: str
    topologia: str
    canale: ChannelProfile
    trasporto: TransportProfile
    punto_di_cattura: str
    immagini: dict[str, str] = field(default_factory=dict)
    visibilita: dict[str, list[list[float]]] = field(default_factory=dict)
    carico: WorkloadProfile = field(default_factory=WorkloadProfile)
    carico_per_stazione: dict[str, dict[str, Any]] = field(default_factory=dict)
    canali_per_nodo: dict[str, dict[str, Any]] = field(default_factory=dict)

    def chiave_profilo(self) -> str:
        parti = [
            self.topologia,
            f"{self.canale.nome}:{self.canale.ritardo_ms}:{self.canale.jitter_ms}:"
            f"{self.canale.perdita_pct}:{self.canale.banda_mbit}"
            + (f":salita{self.canale.strozzatura_salita_mbit:g}"
               if self.canale.strozzatura_salita_mbit else "")
            + (f":ric{self.canale.riconfigurazione_s:g}"
               f"-{self.canale.riconfigurazione_ritardo_max_ms:g}"
               if self.canale.si_riconfigura else "")
            + (f":{self.canale.forma_riconfigurazione}"
               if self.canale.forma_riconfigurazione not in (None, CASUALE) else "")
            + (f":rtt{self.canale.andamento_rtt}-{self.canale.ritardo_ai_bordi_ms:g}"
               if self.canale.varia_nella_finestra else ""),
            f"{self.trasporto.nome}:{self.trasporto.predefinito}:"
            + ",".join(f"{k}={v}" for k, v in sorted(self.trasporto.per_ruolo.items())),
            self.punto_di_cattura,
        ]
        if self.visibilita:
            parti.append("vis:" + ";".join(
                f"{s}=" + ",".join(f"{c[0]:g}-{c[1]:g}" for c in sorted(f))
                for s, f in sorted(self.visibilita.items())))
        if self.carico != WorkloadProfile() or self.carico_per_stazione:
            parti.append("carico:" + repr(sorted(asdict(self.carico).items()))
                         + repr(sorted((k, sorted(v.items()))
                                       for k, v in self.carico_per_stazione.items())))
        if self.canali_per_nodo:
            parti.append("canali:" + repr(sorted((k, sorted(v.items()))
                                                 for k, v in self.canali_per_nodo.items())))
        grezza = "|".join(parti)
        breve = hashlib.sha256(grezza.encode("utf-8")).hexdigest()[:10]
        marchio = "__vis" if self.visibilita else ""
        return f"{self.topologia}__{self.canale.nome}__{self.trasporto.nome}__" \
               f"{self.punto_di_cattura}{marchio}__{breve}"

    def come_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["chiave_profilo"] = self.chiave_profilo()
        try:
            from ids.parametri import parametri_ids
            d["parametri_ids"] = parametri_ids()
        except Exception:
            pass
        return d
