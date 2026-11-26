from __future__ import annotations

import argparse
import json
import signal
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from ids.alarm import Alarm, AlarmEmitter, LocalAlarmLog, StatoAllarmeSuFile
from ids.capture import CapturePoint, crea_punto_di_cattura
from ids.detectors import Detector, rivelatori_predefiniti
from ids.features import FeatureExtractor, FeatureVector
from ids.fusion import LimitatoreFrequenza, ScoreFusion
from ids.profile import NormalityProfile
from model.config import CO_RESIDENTE
from model.events import APP_COMANDO
from sensor.readers import leggi_costo_proprio

if TYPE_CHECKING:
    from ids.detectors import DetectorScore
    from ids.fusion import Decisione

APPRENDIMENTO = "apprendimento"
RILEVAZIONE = "rilevazione"


class ProfiloDiCosto:
    def __init__(self) -> None:
        self.campioni_rss: list[float] = []
        self._cpu_iniziale: float | None = None
        self._cpu_ultima: float | None = None
        self._t_iniziale: float | None = None
        self._t_ultimo: float | None = None

    def campiona(self, adesso: float | None = None) -> None:
        d = leggi_costo_proprio()
        t = adesso if adesso is not None else time.time()
        if "ids_rss_mb" in d:
            self.campioni_rss.append(d["ids_rss_mb"])
        if "ids_cpu_s" in d:
            if self._cpu_iniziale is None:
                self._cpu_iniziale, self._t_iniziale = d["ids_cpu_s"], t
            self._cpu_ultima, self._t_ultimo = d["ids_cpu_s"], t

    def riassunto(self) -> dict[str, float | None]:
        rss = self.campioni_rss
        quota = None
        if (self._cpu_iniziale is not None and self._t_ultimo is not None
                and self._t_ultimo > self._t_iniziale):
            quota = round(100.0 * (self._cpu_ultima - self._cpu_iniziale)
                          / (self._t_ultimo - self._t_iniziale), 3)
        return {
            "campioni": len(rss),
            "rss_mb_medio": round(sum(rss) / len(rss), 3) if rss else None,
            "rss_mb_massimo": round(max(rss), 3) if rss else None,
            "cpu_pct_medio": quota,
            "cpu_s_totale": (round(self._cpu_ultima - self._cpu_iniziale, 3)
                             if self._cpu_iniziale is not None else None),
        }


PAUSA_SEGNALE = 30.0


def leggi_orario(percorso: str | Path, attesa_massima: float = 120.0,
                 pausa: float = 1.0) -> float | None:
    percorso = Path(percorso)
    scadenza = time.time() + attesa_massima
    while time.time() < scadenza:
        try:
            if percorso.exists():
                return float(json.loads(percorso.read_text(encoding="utf-8"))["inizio"])
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(pausa)
    return None


def istante_fine_apprendimento(inizio: float, durata_nominale: float,
                               ritardo_iniziale: float, dall_orario: bool) -> float:
    return inizio + durata_nominale + (ritardo_iniziale if dall_orario else 0.0)


class IdsEngine:
    def __init__(self, cattura: CapturePoint, profilo: NormalityProfile,
                 emettitore: AlarmEmitter, rivelatori: list[Detector] | None = None,
                 estrattore: FeatureExtractor | None = None,
                 fusione: ScoreFusion | None = None) -> None:
        self.cattura = cattura
        self.profilo = profilo
        self.emettitore = emettitore
        self.estrattore = estrattore or FeatureExtractor()
        self.fusione = fusione or ScoreFusion()
        self.limitatore = LimitatoreFrequenza()
        self.modalita = APPRENDIMENTO
        self.primo_sopra_soglia: dict[str, float] = {}
        self._sotto_da: dict[str, float] = {}
        self.costo = ProfiloDiCosto()

        tutti = rivelatori or rivelatori_predefiniti()
        cap = cattura.capacita
        self.rivelatori = [r for r in tutti if r.disponibile(cap)]
        self.esclusi = [r.nome for r in tutti if not r.disponibile(cap)]
        self.finestre_viste = 0
        self.decisioni: list = []

    def passa_a_rilevazione(self) -> None:
        self.profilo.fissa()
        self.modalita = RILEVAZIONE

    def giro(self, adesso: float | None = None) -> list[Decisione]:
        eventi = list(self.cattura.nuovi())
        for ev in eventi:
            if ev.tipo == APP_COMANDO and self.modalita == APPRENDIMENTO:
                self.profilo.apprendi_comando(ev.dati.get("peer", "?"),
                                              ev.dati.get("comando", "?"))
        if eventi and self.modalita == APPRENDIMENTO:
            self.profilo.origine.setdefault("primo_evento_t", eventi[0].t)
        self.estrattore.alimenta(eventi)
        decisioni = []
        for fv in self.estrattore.finestre_pronte(adesso):
            self.finestre_viste += 1
            d = self._valuta(fv)
            if d is not None:
                decisioni.append(d)
        return decisioni

    def _valuta(self, fv: FeatureVector) -> Decisione | None:
        if self.modalita == APPRENDIMENTO:
            self.profilo.apprendi(fv)
            self.profilo.origine["ultima_finestra_t"] = fv.t
            return None
        punteggi = [r.valuta(fv, self.profilo) for r in self.rivelatori]
        d = self.fusione.combina(fv.t, punteggi, assenti=self.esclusi)
        self.decisioni.append(d)
        self._annota_primi_segnali(fv, punteggi)
        if self.limitatore.consenti(d):
            self.emettitore.emetti(AlarmEmitter.da_decisione(d, fv.durata))
        for chi in d.entita_alzate:
            self.emettitore.emetti(AlarmEmitter.da_entita(d, chi, "apertura",
                                                          fv.durata))
        for chi in d.entita_abbassate:
            self.emettitore.emetti(AlarmEmitter.da_entita(d, chi, "chiusura",
                                                          fv.durata))
        return d

    def _annota_primi_segnali(self, fv: FeatureVector, punteggi: list[DetectorScore]) -> None:
        for p in punteggi:
            if not p.attivo:
                continue
            if p.punteggio < self.fusione.soglia:
                self._sotto_da.setdefault(p.nome, fv.t)
                continue
            sotto_da = self._sotto_da.pop(p.nome, None)
            gia_visto = p.nome in self.primo_sopra_soglia
            if gia_visto and (sotto_da is None or fv.t - sotto_da < PAUSA_SEGNALE):
                continue
            self.primo_sopra_soglia.setdefault(p.nome, fv.t)
            forti = sorted(p.contributi.items(), key=lambda kv: -kv[1])[:4]
            self.emettitore.emetti(Alarm(
                t=fv.t, livello="informazione", punteggio=round(p.punteggio, 4),
                motivo=p.motivo or p.principale,
                contributi={p.nome: round(p.punteggio, 4)},
                segnali={f"{p.nome}/{k}": round(v, 4) for k, v in forti},
                rivelatori_attivi=[p.nome], rivelatori_assenti=list(self.esclusi),
                finestra=fv.durata, tipo="primo-segnale"))

    def esegui(self, durata_nominale: float, durata_totale: float,
               periodo: float = 0.5, al_fissaggio: Callable[[], object] | None = None,
               ritardo_iniziale: float = 0.0, inizio_fasi: float | None = None) -> None:
        self._attivo = True
        partenza = inizio_fasi if inizio_fasi is not None else time.time()
        while self._attivo and time.time() - partenza < ritardo_iniziale:
            list(self.cattura.nuovi())
            time.sleep(periodo)
        inizio = partenza if inizio_fasi is not None else time.time()
        fine_apprendimento = istante_fine_apprendimento(
            inizio, durata_nominale, ritardo_iniziale, inizio_fasi is not None)
        while self._attivo and time.time() - inizio < durata_totale:
            if (self.modalita == APPRENDIMENTO
                    and time.time() >= fine_apprendimento):
                self.passa_a_rilevazione()
                if al_fissaggio is not None:
                    al_fissaggio()
            self.giro()
            self.costo.campiona()
            time.sleep(periodo)

    def ferma(self, *_: object) -> None:
        self._attivo = False

    def riepilogo(self) -> dict:
        allarmi = [d for d in self.decisioni if d.appena_alzato]
        return {
            "punto_di_cattura": self.cattura.nome,
            "capacita": {
                "rete": self.cattura.capacita.rete,
                "applicazione": self.cattura.capacita.applicazione,
                "stato_di_bordo": self.cattura.capacita.stato_di_bordo,
            },
            "rivelatori_attivi": [r.nome for r in self.rivelatori],
            "rivelatori_esclusi": self.esclusi,
            "finestre": self.finestre_viste,
            "finestre_del_profilo": self.profilo.finestre,
            "allarmi_alzati": len(allarmi),
            "primo_allarme_t": allarmi[0].t if allarmi else None,
            "costo": self.costo.riassunto(),
        }


def main() -> None:
    ap = argparse.ArgumentParser(description="IDS di bordo")
    ap.add_argument("--vista", required=True, help="vista locale da cui leggere")
    ap.add_argument("--allarmi", required=True, help="file degli allarmi")
    ap.add_argument("--punto-di-cattura", default=CO_RESIDENTE,
                    help="dispiegamento dell'IDS; ammesso solo co-residente")
    ap.add_argument("--chiave-profilo", default="senza-chiave",
                    help="chiave del profilo da apprendere")
    ap.add_argument("--profilo", default=None,
                    help="profilo già appreso da riusare; se assente si apprende")
    ap.add_argument("--salva-profilo", default=None, help="cartella dove salvarlo")
    ap.add_argument("--stato-allarme", default=None,
                    help="file di stato letto per il beacon")
    ap.add_argument("--nominale", type=float, default=900.0,
                    help="durata della fase nominale di apprendimento, s")
    ap.add_argument("--ritardo-avvio", type=float, default=0.0,
                    help="secondi di transitorio da scartare prima di apprendere")
    ap.add_argument("--totale", type=float, default=1800.0,
                    help="durata totale dell'esecuzione, s")
    ap.add_argument("--orario", default=None,
                    help="file in cui l'orchestratore scrive quando partono le fasi")
    ap.add_argument("--riepilogo", default=None,
                    help="file in cui depositare il riepilogo a fine esecuzione")
    args = ap.parse_args()

    avvio_processo = time.time()
    cattura = crea_punto_di_cattura(args.punto_di_cattura, args.vista)
    if args.profilo:
        profilo = NormalityProfile.carica(args.profilo)
        nominale = 0.0
    else:
        profilo = NormalityProfile(chiave=args.chiave_profilo)
        nominale = args.nominale

    sinks = [LocalAlarmLog(args.allarmi)]
    if args.stato_allarme:
        sinks.append(StatoAllarmeSuFile(args.stato_allarme))
    emettitore = AlarmEmitter(sinks)
    motore = IdsEngine(cattura, profilo, emettitore)
    signal.signal(signal.SIGTERM, motore.ferma)
    signal.signal(signal.SIGINT, motore.ferma)
    if nominale == 0.0:
        motore.passa_a_rilevazione()
    salva = (lambda: profilo.salva(args.salva_profilo)) if args.salva_profilo else None
    try:
        motore.esegui(nominale, args.totale, al_fissaggio=salva,
                      ritardo_iniziale=args.ritardo_avvio,
                      inizio_fasi=((leggi_orario(args.orario) or avvio_processo)
                                   if args.orario else None))
    finally:
        if args.salva_profilo:
            profilo.salva(args.salva_profilo)
        riassunto = motore.riepilogo()
        if args.riepilogo:
            try:
                percorso = Path(args.riepilogo)
                percorso.parent.mkdir(parents=True, exist_ok=True)
                percorso.write_text(json.dumps(riassunto, indent=2, ensure_ascii=False),
                                    encoding="utf-8")
            except OSError:
                pass
        print(riassunto)


if __name__ == "__main__":
    main()
