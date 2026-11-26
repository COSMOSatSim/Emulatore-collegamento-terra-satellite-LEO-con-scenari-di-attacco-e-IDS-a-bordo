from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any, Iterable

from model.events import (APP_COMANDO, APP_SESSIONE, BORDO_EVENTO, BORDO_RISORSE,
                          FINESTRA_SEQUENZA, Event, RETE_AGGREGATO, RETE_SOCKET)

FINESTRA_BREVE = 1.0
PASSO = 0.5
FINESTRA_LUNGA = 30.0

NUCLEO = frozenset({
    "pacchetti_s", "byte_s", "nuove_connessioni_s", "sessioni_aperte",
    "ritrasmessi_s", "reset_s", "handshake_falliti_s",
    "rtt_medio_ms", "rtt_min_ms", "durata_media_s", "durata_max_s",
    "comandi_s", "tipi_distinti", "salti_sequenza", "comandi_per_sessione",
    "dim_media", "dim_massima", "peer_distinti",
    "syn_ritrasmessi_s", "socket_in_apertura", "segmenti_connessioni_s",
    "identita_condivise", "identita_cambiate", "identita_fuori_cono",
})

ESTENSIONE_BBR = frozenset({"bbr_bw", "bbr_mrtt", "bbr_gain_medio", "bbr_gain_varianza",
                            "bbr_cadenza_s", "bbr_cicli"})

GUADAGNO_SONDAGGIO = 1.1

GUADAGNO_AVVIO = 2.5
GUADAGNO_SVUOTAMENTO = 0.5


def bbr_informativo(d: dict) -> bool:
    if "bbr_pacing_gain" not in d:
        return False
    if d.get("app_limited") is True:
        return False
    return GUADAGNO_SVUOTAMENTO <= float(d["bbr_pacing_gain"]) <= GUADAGNO_AVVIO


def cadenza_da_storia(storia: list[tuple[float, float]],
                      soglia: float = GUADAGNO_SONDAGGIO) -> tuple[float, float, int]:
    if len(storia) < 2:
        return 0.0, 0.0, 0
    salite: list[float] = []
    precedente = storia[0][1]
    for t, gain in storia[1:]:
        if precedente < soglia <= gain:
            salite.append(t)
        precedente = gain
    if len(salite) < 2:
        return 0.0, 0.0, len(salite)
    intervalli = [b - a for a, b in zip(salite, salite[1:])]
    media = statistics.fmean(intervalli)
    if media <= 0:
        return 0.0, 0.0, len(salite)
    scarto = statistics.pstdev(intervalli) if len(intervalli) > 1 else 0.0
    return media, scarto / media, len(salite)


ESTENSIONE_BORDO = frozenset({"cpu_pct", "memoria_usata_mb", "disco_libero_mb",
                              "processi", "carico_1min", "scritture"})


@dataclass
class FeatureVector:
    t: float
    durata: float
    valori: dict[str, float] = field(default_factory=dict)
    per_peer: dict[str, dict[str, float]] = field(default_factory=dict)
    identita_per_peer: dict[str, str] = field(default_factory=dict)
    attribuzione: dict[str, tuple[str, ...]] = field(default_factory=dict)
    disponibili: frozenset[str] = frozenset()

    def get(self, nome: str, predefinito: float = 0.0) -> float:
        return self.valori.get(nome, predefinito)

    def ha(self, nome: str) -> bool:
        return nome in self.valori

    def come_dict(self) -> dict[str, Any]:
        return {"t": self.t, "valori": self.valori, "per_peer": self.per_peer}


class _Contatori:
    def __init__(self) -> None:
        self._prec: dict[str, tuple[float, float]] = {}

    def tasso(self, nome: str, valore: float, t: float) -> float | None:
        prec = self._prec.get(nome)
        self._prec[nome] = (t, valore)
        if prec is None:
            return None
        dt = t - prec[0]
        if dt <= 0:
            return None
        delta = valore - prec[1]
        if delta < 0:
            return None
        return delta / dt


class FeatureExtractor:
    def __init__(self, finestra: float = FINESTRA_BREVE, passo: float = PASSO,
                 contesto: float = FINESTRA_LUNGA) -> None:
        self.finestra = finestra
        self.passo = passo
        self.contesto = contesto
        self._eventi: list[Event] = []
        self._contatori = _Contatori()
        self._storia_gain: dict[str, list[tuple[float, float]]] = {}
        self._prossima_chiusura: float | None = None
        self._sessioni_aperte_viste: set[str] = set()
        self._flussi_aperti: float | None = None
        self._ultima_condivisa: float | None = None
        self._ultimo_cambio: float | None = None
        self._ultimo_fuori_visibilita: float | None = None
        self._identita_di_peer: dict[str, str] = {}
        self._origine_di_sessione: dict[str, str] = {}
        self._sequenza_di_sessione: dict[str, tuple[float, int]] = {}
        self._salti: list[tuple[float, str]] = []
        self._volumi_di_sessione: dict[str, tuple[float, dict[str, float]]] = {}
        self._volumi: list[tuple[float, str, dict[str, float]]] = []
        self._condivisa_di_peer: dict[str, float] = {}
        self._cambio_di_peer: dict[str, float] = {}
        self._fuori_visibilita_di_peer: dict[str, float] = {}

    def alimenta(self, eventi: Iterable[Event]) -> None:
        for ev in eventi:
            self._eventi.append(ev)
            if ev.tipo == APP_COMANDO:
                self._nota_sequenza(ev)
            elif ev.tipo == RETE_SOCKET:
                self._nota_volumi(ev)
            elif ev.tipo == APP_SESSIONE and ev.dati.get("evento") == "chiusura":
                self._sequenza_di_sessione.pop(str(ev.dati.get("sessione", "")), None)
            if self._prossima_chiusura is None:
                self._prossima_chiusura = ev.t + self.finestra

    CONTATORI_DI_CONNESSIONE = ("byte_ricevuti", "byte_inviati", "segs_in", "segs_out")

    def _nota_volumi(self, ev: Event) -> None:
        sessione = ev.dati.get("sessione")
        if sessione is None:
            return
        chiave = str(sessione)
        adesso = {n: float(ev.dati[n]) for n in self.CONTATORI_DI_CONNESSIONE
                  if ev.dati.get(n) is not None}
        if not adesso:
            return
        prec = self._volumi_di_sessione.get(chiave)
        if prec is None:
            durata = float(ev.dati.get("durata_s") or 0.0)
            delta = dict(adesso) if durata <= self.passo else {}
        else:
            delta = {n: adesso[n] - prec[1][n] for n in adesso
                     if n in prec[1] and adesso[n] >= prec[1][n]}
        if any(x > 0 for x in delta.values()):
            self._volumi.append((ev.t, str(ev.dati.get("peer", "?")), delta))
        self._volumi_di_sessione[chiave] = (ev.t, adesso)

    def _nota_sequenza(self, ev: Event) -> None:
        sessione = ev.dati.get("sessione")
        sequenza = ev.dati.get("sequenza")
        if sessione is None or sequenza is None:
            return
        chiave = str(sessione)
        prec = self._sequenza_di_sessione.get(chiave)
        if prec is not None and ev.t - prec[0] > self.contesto:
            prec = None
        if prec is not None:
            avanti = (int(sequenza) - prec[1]) % FINESTRA_SEQUENZA
            if avanti == 0 or avanti > FINESTRA_SEQUENZA // 2:
                self._salti.append((ev.t, str(ev.dati.get("peer", "?"))))
        self._sequenza_di_sessione[chiave] = (ev.t, int(sequenza))

    def finestre_pronte(self, adesso: float | None = None) -> list[FeatureVector]:
        risultati: list[FeatureVector] = []
        if self._prossima_chiusura is None or not self._eventi:
            return risultati
        ultimo = max(e.t for e in self._eventi)
        limite = adesso if adesso is not None else ultimo
        limite = min(limite, ultimo + self.contesto)
        massimo_per_chiamata = 10_000
        while (self._prossima_chiusura is not None
               and self._prossima_chiusura <= limite
               and len(risultati) < massimo_per_chiamata):
            fine = self._prossima_chiusura
            inizio = fine - self.finestra
            dentro = [e for e in self._eventi if inizio <= e.t < fine]
            risultati.append(self._calcola(dentro, fine))
            self._prossima_chiusura = fine + self.passo
            taglio = fine - self.contesto
            self._eventi = [e for e in self._eventi if e.t >= taglio]
            self._salti = [s for s in self._salti if s[0] >= taglio]
            self._volumi = [x for x in self._volumi if x[0] >= taglio]
            self._volumi_di_sessione = {k: val for k, val
                                        in self._volumi_di_sessione.items()
                                        if val[0] >= taglio}
            self._sequenza_di_sessione = {k: val for k, val
                                          in self._sequenza_di_sessione.items()
                                          if val[0] >= taglio}
            for quando in (self._condivisa_di_peer, self._cambio_di_peer,
                           self._fuori_visibilita_di_peer):
                for p in [p for p, t in quando.items() if t < taglio]:
                    del quando[p]
        return risultati

    def _calcola(self, eventi: list[Event], t_fine: float) -> FeatureVector:
        v: dict[str, float] = {}
        per_peer: dict[str, dict[str, float]] = {}
        attribuzione: dict[str, tuple[str, ...]] = {}
        disponibili: set[str] = set()
        t_inizio = t_fine - self.finestra

        socket_ev = [e for e in eventi if e.tipo == RETE_SOCKET]
        agg_ev = [e for e in eventi if e.tipo == RETE_AGGREGATO]
        cmd_ev = [e for e in eventi if e.tipo == APP_COMANDO]
        sess_ev = [e for e in eventi if e.tipo == APP_SESSIONE]
        bordo_ev = [e for e in eventi if e.tipo == BORDO_RISORSE]
        bordo_evt = [e for e in eventi if e.tipo == BORDO_EVENTO]

        if socket_ev:
            ultimi: dict[str, dict] = {}
            for e in socket_ev:
                ultimi[e.dati.get("sessione", "?")] = e.dati
            v["sessioni_aperte"] = float(len(ultimi))
            mezze = sum(1 for d in ultimi.values() if d.get("stato") == "SYN-RECV")
            if mezze:
                v["socket_in_apertura"] = float(mezze)
            rtt = [d["rtt_ms"] for d in ultimi.values() if "rtt_ms" in d]
            minrtt = [d["minrtt_ms"] for d in ultimi.values() if "minrtt_ms" in d]
            durate = [d["durata_s"] for d in ultimi.values() if "durata_s" in d]
            if rtt:
                v["rtt_medio_ms"] = statistics.fmean(rtt)
            if minrtt:
                v["rtt_min_ms"] = min(minrtt)
            if durate:
                v["durata_media_s"] = statistics.fmean(durate)
                v["durata_max_s"] = max(durate)
            peer = {d.get("peer", "?") for d in ultimi.values()}
            v["peer_distinti"] = float(len(peer))

            gains = [d["bbr_pacing_gain"] for d in ultimi.values() if bbr_informativo(d)]
            if gains:
                v["bbr_gain_medio"] = statistics.fmean(gains)
                v["bbr_gain_varianza"] = statistics.pvariance(gains) if len(gains) > 1 else 0.0
                disponibili |= {"bbr_gain_medio", "bbr_gain_varianza"}

            for d in ultimi.values():
                if not bbr_informativo(d):
                    continue
                chiave = d.get("peer", "?")
                storia = self._storia_gain.setdefault(chiave, [])
                storia.append((t_fine, float(d["bbr_pacing_gain"])))
                taglio = t_fine - self.contesto
                if storia and storia[0][0] < taglio:
                    self._storia_gain[chiave] = [x for x in storia if x[0] >= taglio]

            cadenze = []
            for chiave, storia in self._storia_gain.items():
                media, cv, cicli = cadenza_da_storia(storia)
                if cicli >= 2:
                    cadenze.append(media)
                    voce = per_peer.setdefault(chiave, {})
                    voce["bbr_cadenza_s"] = media
                    voce["bbr_cadenza_cv"] = cv
                    voce["bbr_cicli"] = float(cicli)
            if cadenze:
                v["bbr_cadenza_s"] = statistics.fmean(cadenze)
                v["bbr_cicli"] = float(len(cadenze))
                disponibili |= {"bbr_cadenza_s", "bbr_cicli"}
            bw = [d["bbr_bw"] for d in ultimi.values() if "bbr_bw" in d and bbr_informativo(d)]
            if bw:
                v["bbr_bw"] = statistics.fmean(bw)
                disponibili.add("bbr_bw")
            mrtt = [d["bbr_mrtt"] for d in ultimi.values()
                    if "bbr_mrtt" in d and bbr_informativo(d)]
            if mrtt:
                v["bbr_mrtt"] = statistics.fmean(mrtt)
                disponibili.add("bbr_mrtt")

            for d in ultimi.values():
                p = d.get("peer", "?")
                voce = per_peer.setdefault(p, {})
                voce["sessioni"] = voce.get("sessioni", 0.0) + 1.0
                if "minrtt_ms" in d:
                    voce["rtt_min_ms"] = min(voce.get("rtt_min_ms", 1e9), d["minrtt_ms"])
                if "durata_s" in d:
                    voce["durata_max_s"] = max(voce.get("durata_max_s", 0.0), d["durata_s"])
                if bbr_informativo(d):
                    voce.setdefault("_gains", 0.0)
                    voce["_gains"] += 1.0
                    voce["bbr_gain_medio"] = (
                        voce.get("bbr_gain_medio", 0.0) * (voce["_gains"] - 1)
                        + d["bbr_pacing_gain"]) / voce["_gains"]
                    if "bbr_mrtt" in d:
                        voce["bbr_mrtt"] = min(voce.get("bbr_mrtt", 1e9), d["bbr_mrtt"])
                    if "bbr_bw" in d:
                        voce["bbr_bw"] = max(voce.get("bbr_bw", 0.0), d["bbr_bw"])
            for voce in per_peer.values():
                voce.pop("_gains", None)

        if agg_ev:
            ultimo = agg_ev[-1]
            mappa = {
                "Tcp.InSegs": "segmenti_in_s", "Tcp.OutSegs": "segmenti_out_s",
                "Tcp.RetransSegs": "ritrasmessi_s", "Tcp.OutRsts": "reset_s",
                "Tcp.AttemptFails": "handshake_falliti_s", "Tcp.PassiveOpens": "nuove_connessioni_s",
                "TcpExt.TCPSynRetrans": "syn_ritrasmessi_s",
                "IpExt.InOctets": "byte_in_s", "IpExt.OutOctets": "byte_out_s",
            }
            for chiave, nome in mappa.items():
                if chiave in ultimo.dati:
                    r = self._contatori.tasso(chiave, float(ultimo.dati[chiave]), ultimo.t)
                    if r is not None:
                        v[nome] = r
            if "segmenti_in_s" in v or "segmenti_out_s" in v:
                v["pacchetti_s"] = v.get("segmenti_in_s", 0.0) + v.get("segmenti_out_s", 0.0)
            if "byte_in_s" in v or "byte_out_s" in v:
                v["byte_s"] = v.get("byte_in_s", 0.0) + v.get("byte_out_s", 0.0)

        tratti = [(p, d) for t, p, d in self._volumi if t_inizio <= t < t_fine]
        if tratti:
            durata = max(self.finestra, 1e-9)
            somma: dict[str, float] = {}
            for _, d in tratti:
                for nome, x in d.items():
                    somma[nome] = somma.get(nome, 0.0) + x
            if "byte_ricevuti" in somma:
                v["byte_in_s"] = somma["byte_ricevuti"] / durata
            if "byte_inviati" in somma:
                v["byte_out_s"] = somma["byte_inviati"] / durata
            if "byte_in_s" in v or "byte_out_s" in v:
                v["byte_s"] = v.get("byte_in_s", 0.0) + v.get("byte_out_s", 0.0)
            if "segs_in" in somma or "segs_out" in somma:
                v["segmenti_connessioni_s"] = (somma.get("segs_in", 0.0)
                                               + somma.get("segs_out", 0.0)) / durata
            disponibili |= {k for k in ("byte_in_s", "byte_out_s", "byte_s",
                                        "segmenti_connessioni_s") if k in v}
            for peer, d in tratti:
                voce = per_peer.setdefault(peer, {})
                for sorgente, destinazione in (("byte_ricevuti", "byte_in"),
                                               ("byte_inviati", "byte_out"),
                                               ("segs_in", "segmenti_in"),
                                               ("segs_out", "segmenti_out")):
                    if sorgente in d:
                        voce[destinazione] = voce.get(destinazione, 0.0) + d[sorgente]
                if "byte_in" in voce or "byte_out" in voce:
                    voce["byte"] = voce.get("byte_in", 0.0) + voce.get("byte_out", 0.0)

        if cmd_ev:
            durata = max(self.finestra, 1e-9)
            v["comandi_s"] = len(cmd_ev) / durata
            tipi = {e.dati.get("comando", "?") for e in cmd_ev}
            v["tipi_distinti"] = float(len(tipi))
            dim = [float(e.dati.get("dimensione", 0)) for e in cmd_ev]
            if dim:
                v["dim_media"] = statistics.fmean(dim)
                v["dim_massima"] = max(dim)
            v["salti_sequenza"] = float(sum(1 for t, _ in self._salti
                                            if t_inizio <= t < t_fine))
            if v.get("sessioni_aperte"):
                v["comandi_per_sessione"] = len(cmd_ev) / v["sessioni_aperte"]
            for e in cmd_ev:
                dichiarata = e.dati.get("identita")
                if dichiarata:
                    self._identita_di_peer[str(e.dati.get("peer", "?"))] = str(dichiarata)
                chi = str(e.dati.get("peer", "?"))
                if float(e.dati.get("identita_origini", 0) or 0) > 1:
                    self._ultima_condivisa = max(self._ultima_condivisa or 0.0, e.t)
                    self._condivisa_di_peer[chi] = max(
                        self._condivisa_di_peer.get(chi, 0.0), e.t)
                if e.dati.get("identita_cambiata"):
                    self._ultimo_cambio = max(self._ultimo_cambio or 0.0, e.t)
                    self._cambio_di_peer[chi] = max(
                        self._cambio_di_peer.get(chi, 0.0), e.t)
                if e.dati.get("fuori_cono"):
                    self._ultimo_fuori_visibilita = max(self._ultimo_fuori_visibilita or 0.0,
                                                  e.t)
                    self._fuori_visibilita_di_peer[chi] = max(
                        self._fuori_visibilita_di_peer.get(chi, 0.0), e.t)

            for e in cmd_ev:
                p = e.dati.get("peer", "?")
                voce = per_peer.setdefault(p, {})
                voce["comandi"] = voce.get("comandi", 0.0) + 1.0
                voce[f"cmd_{e.dati.get('comando', '?')}"] = \
                    voce.get(f"cmd_{e.dati.get('comando', '?')}", 0.0) + 1.0
                origini = float(e.dati.get("identita_origini", 0) or 0)
                if origini:
                    voce["identita_origini"] = max(voce.get("identita_origini", 0.0),
                                                   origini)
                if e.dati.get("identita_cambiata"):
                    voce["identita_cambiata"] = 1.0

            for p, voce in per_peer.items():
                suoi = [t for t, q in self._salti if q == p]
                dentro = sum(1 for t in suoi if t_inizio <= t < t_fine)
                if dentro:
                    voce["salti_sequenza"] = float(dentro)
                elif any(0.0 <= t_fine - t <= self.contesto for t in suoi):
                    voce["salti_sequenza"] = 1.0
            disponibili |= {"comandi_s", "tipi_distinti", "dim_media", "salti_sequenza"}

        if sess_ev:
            for e in sess_ev:
                if "flussi_aperti" in e.dati:
                    self._flussi_aperti = float(e.dati["flussi_aperti"])
                sessione = e.dati.get("sessione")
                if not sessione:
                    continue
                if e.dati.get("evento") == "apertura" and e.dati.get("peer"):
                    self._origine_di_sessione[str(sessione)] = str(e.dati["peer"])
                elif e.dati.get("evento") == "chiusura":
                    self._origine_di_sessione.pop(str(sessione), None)
            aperture = sum(1 for e in sess_ev if e.dati.get("evento") == "apertura")
            if aperture:
                v["nuove_connessioni_s"] = max(
                    v.get("nuove_connessioni_s", 0.0),
                    aperture / max(self.finestra, 1e-9))
        if self._flussi_aperti is not None:
            v["sessioni_aperte"] = max(v.get("sessioni_aperte", 0.0),
                                       self._flussi_aperti)

        for origine in set(self._origine_di_sessione.values()):
            per_peer.setdefault(origine, {})

        for nome, ultimo, di_peer in (
                ("identita_condivise", self._ultima_condivisa,
                 self._condivisa_di_peer),
                ("identita_cambiate", self._ultimo_cambio, self._cambio_di_peer),
                ("identita_fuori_cono", self._ultimo_fuori_visibilita,
                 self._fuori_visibilita_di_peer)):
            if ultimo is not None and 0.0 <= t_fine - ultimo <= self.contesto:
                v[nome] = 1.0
                disponibili.add(nome)
                indirizzi = tuple(sorted(p for p, t in di_peer.items()
                                         if 0.0 <= t_fine - t <= self.contesto))
                if indirizzi:
                    attribuzione[nome] = indirizzi

        if bordo_ev:
            ultimo = bordo_ev[-1].dati
            for nome in ("cpu_pct", "memoria_usata_mb", "disco_libero_mb",
                         "processi", "carico_1min"):
                if nome in ultimo:
                    v[nome] = float(ultimo[nome])
                    disponibili.add(nome)
        if bordo_evt:
            v["scritture"] = float(sum(1 for e in bordo_evt
                                       if e.dati.get("evento") == "scrittura"))
            disponibili.add("scritture")

        disponibili |= {k for k in v if k in NUCLEO}
        identita = {p: i for p, i in self._identita_di_peer.items() if p in per_peer}
        return FeatureVector(t=t_fine, durata=self.finestra, valori=v,
                             per_peer=per_peer, identita_per_peer=identita,
                             attribuzione=attribuzione,
                             disponibili=frozenset(disponibili))
