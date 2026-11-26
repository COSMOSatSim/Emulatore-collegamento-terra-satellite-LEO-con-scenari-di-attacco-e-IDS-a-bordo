from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from matplotlib.axes import Axes
    from matplotlib.figure import Figure
    from types import ModuleType

SUPERFICIE = "#fcfcfb"
INCHIOSTRO = "#0b0b0b"
SECONDARIO = "#52514e"
TENUE = "#898781"
GRIGLIA = "#e1e0d9"
ASSE = "#c3c2b7"
NEUTRO = "#f0efec"
SERIE = ("#2a78d6", "#eb6834", "#1baf7a")
SEQUENZIALE = ("#cde2fb", "#b7d3f6", "#9ec5f4", "#86b6ef", "#6da7ec", "#5598e7",
               "#3987e5", "#2a78d6", "#256abf", "#1c5cab", "#184f95", "#104281",
               "#0d366b")
STATO = {"rilevato": "#0ca30c", "attenzione": "#fab219", "mancato": "#d03b3b"}

RIVELATORI = ("volumetrico", "coerenza-identita", "grammatica", "deviazione-bordo")
NOMI_RIVELATORI = {"volumetrico": "volumetrico", "coerenza-identita": "identità",
                   "grammatica": "grammatica", "deviazione-bordo": "stato di bordo"}
DISPIEGAMENTI = {"co-residente": "a bordo", "in-linea": "in linea"}


def numero(x: float | None, cifre: int = 1) -> str:
    if x is None:
        return "-"
    if isinstance(x, float) and math.isnan(x):
        return "-"
    return f"{x:.{cifre}f}".replace(".", ",")


@dataclass
class Esecuzione:
    cartella: Path
    metriche: dict[str, Any]
    allarmi: list[dict] = field(default_factory=list)
    fasi: dict[str, tuple[float, float]] = field(default_factory=dict)
    onnisciente: dict[str, Any] = field(default_factory=dict)

    @property
    def run_id(self) -> str:
        return self.metriche.get("run_id", self.cartella.name)

    @property
    def scenario(self) -> str:
        return self.metriche.get("scenario", "?")

    @property
    def scenario_base(self) -> str:
        return re.sub(r"-(STD|BBR)$", "", self.scenario)

    @property
    def trasporto(self) -> str:
        return self.metriche.get("trasporto", "?")

    def scenario_con(self, trasporto: bool) -> str:
        if not trasporto or self.trasporto in ("", "?"):
            return self.scenario_base
        return f"{self.scenario_base} {self.trasporto}"

    @property
    def con_attacco(self) -> bool:
        return "attacco" in self.fasi

    @property
    def punto(self) -> str:
        return self.metriche.get("punto_di_cattura", "?")


def _trova(radice: Path, *nomi: str) -> Path | None:
    for n in nomi:
        if (radice / n).exists():
            return radice / n
    for n in nomi:
        trovati = sorted(radice.rglob(Path(n).name))
        if trovati:
            return trovati[0]
    return None


def _righe(f: Path | None) -> list[dict]:
    if f is None:
        return []
    out = []
    for riga in f.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            out.append(json.loads(riga))
        except ValueError:
            continue
    return out


def fasi_da_etichette(etichette: list[dict]) -> dict[str, tuple[float, float]]:
    aperte: dict[str, float] = {}
    fasi: dict[str, tuple[float, float]] = {}
    for e in etichette:
        if e.get("etichetta") != "fase":
            continue
        nome, evento = e["dati"].get("nome"), e["dati"].get("evento")
        if evento == "inizio":
            aperte[nome] = float(e["t"])
        elif evento == "fine" and nome in aperte:
            fasi[nome] = (aperte.pop(nome), float(e["t"]))
    return fasi


def carica_esecuzione(cartella: Path) -> Esecuzione | None:
    f = _trova(cartella, "metriche.json")
    if f is None:
        return None
    try:
        d = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    esecuzioni = d.get("esecuzioni") or []
    if not esecuzioni:
        return None
    onn: dict[str, Any] = {}
    fo = _trova(cartella, "onnisciente.json")
    if fo is not None:
        try:
            v = json.loads(fo.read_text(encoding="utf-8"))
            onn = next((x for x in v.values() if isinstance(x, dict)), {}) \
                if "telai" not in v else v
        except (OSError, ValueError, StopIteration):
            onn = {}
    return Esecuzione(
        cartella=cartella, metriche=esecuzioni[0],
        allarmi=_righe(_trova(cartella, "local/allarmi.jsonl", "allarmi.jsonl")),
        fasi=fasi_da_etichette(_righe(_trova(cartella, "truth/etichette.jsonl",
                                             "etichette.jsonl"))),
        onnisciente=onn)


def escluse(cartella: Path) -> set[str]:
    f = cartella / "escluse.txt"
    if not f.exists():
        return set()
    return {r.split()[0] for r in f.read_text(encoding="utf-8").splitlines()
            if r.strip() and not r.startswith("#")}


def carica_serie(cartella: str | Path) -> list[Esecuzione]:
    cartella = Path(cartella)
    via = escluse(cartella)
    esecuzioni = []
    for d in sorted(p for p in cartella.iterdir() if p.is_dir()):
        if d.name in ("grafici", "confronti", "taratura", "local") or d.name in via:
            continue
        e = carica_esecuzione(d)
        if e is not None:
            esecuzioni.append(e)
    def inizio(e: Esecuzione) -> float:
        return min((a for a, _ in e.fasi.values()), default=0.0)
    return sorted(esecuzioni, key=inizio)


def latenza(e: Esecuzione) -> float | None:
    if e.metriche.get("gia_in_allarme"):
        return None
    return e.metriche.get("latenza_s")


def esito(e: Esecuzione) -> str:
    if e.metriche.get("gia_in_allarme"):
        return "già in allarme"
    return "rilevato" if e.metriche.get("rilevato") else "mancato"


def primi_in_finestra(e: Esecuzione) -> dict[str, float]:
    pf = e.metriche.get("primo_in_finestra_s")
    if pf:
        return dict(pf)
    return {k: v for k, v in (e.metriche.get("primo_segnale_s") or {}).items()
            if v is not None and v >= 0}


def servizio(e: Esecuzione) -> float | None:
    s = e.metriche.get("servizio") or {}
    if s.get("servizio_mantenuto") is not None:
        return s["servizio_mantenuto"]
    return s.get("servizio_mantenuto_su_quiete")


def segnali_dei_falsi_positivi(e: Esecuzione, coda: float = 300.0) -> dict[str, int]:
    a0, a1 = e.fasi.get("attacco", (None, None))
    fine = e.fasi.get("osservazione", (None, a1))[1] if a1 is not None else None
    conta: dict[str, int] = {}
    for a in e.allarmi:
        if a.get("tipo") != "apertura":
            continue
        t = float(a["t"])
        dentro = a0 is not None and a0 <= t <= (fine or a1) + coda
        if dentro:
            continue
        for k, v in (a.get("segnali") or {}).items():
            if v <= 0:
                continue
            rivelatore, _, nome = k.partition("/")
            nome = re.sub(r"^[0-9.]+:", "", nome)
            chiave = f"{NOMI_RIVELATORI.get(rivelatore, rivelatore)}: {nome}"
            conta[chiave] = conta.get(chiave, 0) + 1
    return conta


def riassunto(esecuzioni: list[Esecuzione]) -> dict[str, Any]:
    attacchi = [e for e in esecuzioni if e.con_attacco]
    rilevati = [e for e in attacchi if e.metriche.get("rilevato")]
    latenze = [x for x in (latenza(e) for e in rilevati) if x is not None]
    esposizione = sum(e.metriche.get("durata_esposizione_s") or 0 for e in esecuzioni)
    fp = sum(e.metriche.get("falsi_positivi") or 0 for e in esecuzioni)
    costi = [e.metriche.get("costo") or {} for e in esecuzioni]
    cpu = [c["cpu_pct_medio"] for c in costi if c.get("cpu_pct_medio") is not None]
    rss = [c["rss_mb_massimo"] for c in costi if c.get("rss_mb_massimo") is not None]
    return {
        "esecuzioni": len(esecuzioni), "attacchi": len(attacchi),
        "rilevati": len(rilevati),
        "gia_in_allarme": sum(1 for e in attacchi if e.metriche.get("gia_in_allarme")),
        "latenza_mediana_s": statistics.median(latenze) if latenze else None,
        "latenza_massima_s": max(latenze) if latenze else None,
        "falsi_positivi": fp,
        "falsi_positivi_per_ora": fp / (esposizione / 3600.0) if esposizione > 0 else None,
        "cpu_pct_medio": (min(cpu), max(cpu)) if cpu else None,
        "rss_mb_massimo": (min(rss), max(rss)) if rss else None,
        "generazioni": sorted({str(e.metriche.get("generazione")) for e in esecuzioni}),
    }


def _pyplot() -> ModuleType:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({
        "figure.facecolor": SUPERFICIE, "axes.facecolor": SUPERFICIE,
        "savefig.facecolor": SUPERFICIE, "axes.edgecolor": ASSE,
        "axes.labelcolor": SECONDARIO, "axes.titlecolor": INCHIOSTRO,
        "text.color": INCHIOSTRO, "xtick.color": TENUE, "ytick.color": SECONDARIO,
        "axes.grid": True, "grid.color": GRIGLIA, "grid.linewidth": 0.8,
        "grid.linestyle": "-", "axes.spines.top": False, "axes.spines.right": False,
        "axes.spines.left": False, "axes.axisbelow": True,
        "font.family": "sans-serif", "font.size": 9, "axes.titlesize": 11,
        "axes.titleweight": "bold", "axes.titlelocation": "left",
        "legend.frameon": False, "legend.fontsize": 8.5,
    })
    return plt


def _salva(fig: Figure, uscita: Path, nome: str) -> str:
    uscita.mkdir(parents=True, exist_ok=True)
    fig.savefig(uscita / f"{nome}.png", dpi=150, bbox_inches="tight")
    import matplotlib.pyplot as plt
    plt.close(fig)
    return f"{nome}.png"


def _titolo(ax: Axes, titolo: str, sottotitolo: str = "") -> None:
    ax.set_title(titolo, loc="left", pad=16 if sottotitolo else 6)
    if sottotitolo:
        ax.text(0, 1.0, sottotitolo, transform=ax.transAxes, fontsize=8.5,
                color=SECONDARIO, va="bottom", ha="left")


def _titolo_figura(fig: Figure, titolo: str, sottotitolo: str = "") -> None:
    fig.text(0.01, 1.0, titolo, fontsize=11, fontweight="bold", color=INCHIOSTRO,
             ha="left", va="bottom")
    if sottotitolo:
        fig.text(0.01, 0.985, sottotitolo, fontsize=8.5, color=SECONDARIO,
                 ha="left", va="top")


def _virgola(*assi: Axes, asse: str = "x") -> None:
    from matplotlib.ticker import FuncFormatter
    formato = FuncFormatter(lambda v, _p: (f"{v:g}").replace(".", ","))
    for ax in assi:
        (ax.xaxis if asse == "x" else ax.yaxis).set_major_formatter(formato)


def _punti(ax: Axes, x: Sequence[float], y: Sequence[float], colore: str,
           etichetta: str | None = None, vuoto: bool = False, **kw: Any) -> None:
    ax.scatter(x, y, s=56, color=SUPERFICIE if vuoto else colore,
               edgecolors=colore if vuoto else SUPERFICIE,
               linewidths=1.6 if vuoto else 2.0, zorder=3, label=etichetta, **kw)


def figura_latenze(esecuzioni: list[Esecuzione], uscita: Path, nome_serie: str) -> str | None:
    plt = _pyplot()
    attacchi = [e for e in esecuzioni if e.con_attacco]
    if not attacchi:
        return None
    ordinati = sorted(attacchi, key=lambda e: (latenza(e) is None, latenza(e) or 0))
    fig, ax = plt.subplots(figsize=(7.5, 0.32 * len(ordinati) + 1.6))
    y = list(range(len(ordinati)))[::-1]
    massimo = max([latenza(e) or 1 for e in ordinati] + [10]) * 3
    visti = set()
    for yi, e in zip(y, ordinati):
        colore = SERIE[0] if e.punto == "co-residente" else SERIE[1]
        etichetta = DISPIEGAMENTI.get(e.punto, e.punto)
        lat = latenza(e)
        if esito(e) == "rilevato" and lat is not None:
            _punti(ax, [max(lat, 0.05)], [yi], colore,
                   etichetta if etichetta not in visti else None)
            visti.add(etichetta)
        elif esito(e) == "già in allarme":
            _punti(ax, [massimo], [yi], STATO["attenzione"], vuoto=True)
            ax.text(massimo * 1.15, yi, "già in allarme", va="center", fontsize=8,
                    color=SECONDARIO)
        else:
            ax.scatter([massimo], [yi], marker="x", s=46, color=STATO["mancato"],
                       linewidths=2, zorder=3)
            ax.text(massimo * 1.15, yi, "non rilevato", va="center", fontsize=8,
                    color=SECONDARIO)
    ax.set_yticks(y, [f"{e.scenario}" for e in ordinati])
    ax.set_xscale("log")
    ax.set_xlim(0.2, massimo * 6)
    ax.set_xticks([0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500],
                  ["0,5", "1", "2", "5", "10", "20", "50", "100", "200", "500"])
    ax.set_xlabel("secondi dall'apertura della finestra d'attacco (scala logaritmica)")
    ax.grid(axis="y", visible=False)
    r = riassunto(esecuzioni)
    estremi = [(latenza(e), yi) for yi, e in zip(y, ordinati) if latenza(e) is not None
               and esito(e) == "rilevato"]
    for lat, yi in (min(estremi), max(estremi)) if estremi else ():
        ax.text(lat * 1.18, yi, f"{numero(lat)} s", va="center", fontsize=8,
                color=SECONDARIO)
    _titolo(ax, "Latenza di rilevazione per scenario",
            f"{nome_serie} - rilevati {r['rilevati']} su {r['attacchi']}, "
            f"mediana {numero(r['latenza_mediana_s'])} s")
    if len(visti) > 1:
        ax.legend(loc="lower right")
    return _salva(fig, uscita, "latenze")


def figura_primo_rivelatore(esecuzioni: list[Esecuzione], uscita: Path,
                            nome_serie: str) -> str | None:
    plt = _pyplot()
    from matplotlib.colors import ListedColormap, LogNorm
    attacchi = [e for e in esecuzioni if e.con_attacco]
    if not attacchi:
        return None
    righe = [[primi_in_finestra(e).get(r) for r in RIVELATORI] for e in attacchi]
    fig, ax = plt.subplots(figsize=(6.4, 0.32 * len(attacchi) + 1.8))
    mappa = ListedColormap(SEQUENZIALE[1:12])
    norma = LogNorm(vmin=0.3, vmax=1000)
    import numpy as np
    valori = np.array([[v if v is not None and v > 0 else np.nan for v in r] for r in righe])
    ax.imshow(np.where(np.isnan(valori), 1, valori), cmap=mappa, norm=norma,
              aspect="auto", alpha=np.where(np.isnan(valori), 0.0, 1.0))
    for i, r in enumerate(righe):
        presenti = [(v, j) for j, v in enumerate(r) if v is not None and v > 0]
        primo = min(presenti)[1] if presenti else None
        for j, v in enumerate(r):
            if v is None or v <= 0:
                ax.add_patch(plt.Rectangle((j - 0.5, i - 0.5), 1, 1, color=NEUTRO, zorder=1))
                ax.text(j, i, "-", ha="center", va="center", fontsize=8, color=TENUE)
                continue
            scuro = norma(v) > 0.45
            ax.text(j, i, numero(v, 1 if v < 100 else 0), ha="center", va="center",
                    fontsize=8, color="white" if scuro else INCHIOSTRO,
                    fontweight="bold" if j == primo else "normal")
    ax.set_xticks(range(len(RIVELATORI)), [NOMI_RIVELATORI[r] for r in RIVELATORI])
    ax.set_yticks(range(len(attacchi)), [e.scenario for e in attacchi])
    ax.grid(False)
    ax.tick_params(length=0)
    for lato in ("bottom", "top", "left", "right"):
        ax.spines[lato].set_visible(False)
    barra = fig.colorbar(plt.cm.ScalarMappable(norm=norma, cmap=mappa), ax=ax,
                         fraction=0.04, pad=0.02)
    barra.set_label("secondi dall'apertura (scala logaritmica)", color=SECONDARIO)
    barra.outline.set_visible(False)
    _titolo(ax, "Primo superamento di soglia per rivelatore",
            f"{nome_serie} - nella finestra d'attacco; in grassetto il primo; "
            f"'-' nessuno")
    return _salva(fig, uscita, "primo-rivelatore")


def figura_falsi_positivi(esecuzioni: list[Esecuzione], uscita: Path,
                          nome_serie: str) -> str | None:
    plt = _pyplot()
    riposo = [e for e in esecuzioni if not e.con_attacco]
    segnali: dict[str, int] = {}
    for e in esecuzioni:
        for k, v in segnali_dei_falsi_positivi(e).items():
            segnali[k] = segnali.get(k, 0) + v
    if not riposo and not segnali:
        return None
    fig, assi = plt.subplots(1, 2, figsize=(10, max(2.4, 0.34 * max(len(riposo), len(segnali), 3) + 1.4)),
                             gridspec_kw={"wspace": 0.9})
    ax = assi[0]
    if riposo:
        y = list(range(len(riposo)))[::-1]
        valori = [e.metriche.get("falsi_positivi_per_ora") or 0 for e in riposo]
        ax.barh(y, valori, height=0.55, color=SERIE[0])
        for yi, e, v in zip(y, riposo, valori):
            minuti = (e.metriche.get("durata_esposizione_s") or 0) / 60
            ax.text(v + max(valori + [1]) * 0.02, yi,
                    f"{e.metriche.get('falsi_positivi', 0)} in {numero(minuti, 0)} min",
                    va="center", fontsize=8, color=SECONDARIO)
        ax.set_yticks(y, [e.scenario for e in riposo])
        ax.set_xlim(0, max(valori + [1]) * 1.6)
        ax.set_xlabel("allarmi all'ora senza attacco")
        ax.grid(axis="y", visible=False)
    else:
        ax.axis("off")
    r = riassunto(esecuzioni)
    _titolo_figura(fig, "Falsi positivi e segnali di apertura",
                   f"{nome_serie} - {r['falsi_positivi']} aperture fuori finestra nella "
                   f"serie, {numero(r['falsi_positivi_per_ora'])} all'ora di esposizione")
    ax.set_title("nelle esecuzioni senza attacco", loc="left", fontsize=9, fontweight="normal",
                 color=SECONDARIO)
    _virgola(ax)
    ax = assi[1]
    if segnali:
        voci = sorted(segnali.items(), key=lambda kv: kv[1])
        y = range(len(voci))
        ax.barh(list(y), [v for _, v in voci], height=0.55, color=SERIE[0])
        for yi, (_, v) in zip(y, voci):
            ax.text(v + 0.1, yi, str(v), va="center", fontsize=8, color=SECONDARIO)
        ax.set_yticks(list(y), [k for k, _ in voci])
        ax.set_xlabel("aperture fuori finestra con il segnale presente")
        ax.grid(axis="y", visible=False)
        ax.set_title("segnali presenti nelle aperture fuori finestra", loc="left",
                     fontsize=9, fontweight="normal", color=SECONDARIO)
        ax.xaxis.get_major_locator().set_params(integer=True)
    else:
        ax.axis("off")
    return _salva(fig, uscita, "falsi-positivi")


def figura_costo(esecuzioni: list[Esecuzione], uscita: Path, nome_serie: str) -> str | None:
    plt = _pyplot()
    con_costo = [e for e in esecuzioni if (e.metriche.get("costo") or {}).get("cpu_pct_medio") is not None]
    if not con_costo:
        return None
    fig, assi = plt.subplots(1, 2, figsize=(10, 0.3 * len(con_costo) + 1.8), sharey=True,
                             gridspec_kw={"wspace": 0.08})
    y = list(range(len(con_costo)))[::-1]
    for ax, campo, etichetta in ((assi[0], "cpu_pct_medio", "CPU media del processo dell'IDS (%)"),
                                 (assi[1], "rss_mb_massimo", "memoria massima del processo (MB)")):
        visti = set()
        for yi, e in zip(y, con_costo):
            colore = SERIE[0] if e.punto == "co-residente" else SERIE[1]
            nome = DISPIEGAMENTI.get(e.punto, e.punto)
            _punti(ax, [e.metriche["costo"][campo]], [yi], colore,
                   nome if nome not in visti else None)
            visti.add(nome)
        ax.set_xlabel(etichetta)
        ax.set_xlim(left=0)
        ax.grid(axis="y", visible=False)
    assi[0].set_yticks(y, [e.scenario for e in con_costo])
    if len(visti) > 1:
        assi[1].legend(loc="lower right")
    r = riassunto(esecuzioni)
    cpu, rss = r["cpu_pct_medio"], r["rss_mb_massimo"]
    _titolo_figura(fig, "Costo dell'IDS",
                   f"{nome_serie} - CPU fra {numero(cpu[0], 2)} e {numero(cpu[1], 2)}%, "
                   f"memoria fino a {numero(rss[1])} MB, misurate sul processo")
    _virgola(*assi)
    return _salva(fig, uscita, "costo-ids")


def figura_servizio(esecuzioni: list[Esecuzione], uscita: Path, nome_serie: str) -> str | None:
    plt = _pyplot()
    con = [(e, servizio(e)) for e in esecuzioni if e.con_attacco and servizio(e) is not None]
    if not con:
        return None
    con.sort(key=lambda c: c[1])
    fig, ax = plt.subplots(figsize=(7.5, 0.3 * len(con) + 1.6))
    y = list(range(len(con)))[::-1]
    ax.axvline(1.0, color=ASSE, linewidth=1, zorder=1)
    for yi, (e, s) in zip(y, con):
        basso = s < 0.95
        _punti(ax, [s], [yi], SERIE[1] if basso else TENUE)
        if basso:
            ax.text(s - 0.015, yi, numero(s, 2), va="center", ha="right", fontsize=8,
                    color=SECONDARIO)
    ax.set_yticks(y, [e.scenario for e, _ in con])
    ax.set_xlim(min(0.6, min(s for _, s in con) - 0.1), 1.25)
    ax.set_xlabel("comandi legittimi/s, attacco su riferimento (1 = invariato)")
    ax.grid(axis="y", visible=False)
    _titolo(ax, "Servizio mantenuto dalle stazioni legittime",
            f"{nome_serie} - in evidenza gli scenari sotto 0,95")
    _virgola(ax)
    return _salva(fig, uscita, "servizio")


def figura_cronologia(esecuzioni: list[Esecuzione], uscita: Path, nome_serie: str) -> str | None:
    plt = _pyplot()
    righe = [e for e in esecuzioni if e.fasi]
    if not righe:
        return None
    fig, ax = plt.subplots(figsize=(10, 0.3 * len(righe) + 1.8))
    y = list(range(len(righe)))[::-1]
    estremo_sx, estremo_dx = -300.0, 0.0
    for yi, e in zip(y, righe):
        rif = e.fasi.get("attacco", e.fasi.get("quiete", (min(a for a, _ in e.fasi.values()), 0)))[0]
        if "attacco" in e.fasi:
            a0, a1 = e.fasi["attacco"]
            ax.barh(yi, a1 - a0, left=0, height=0.8, color=SERIE[0], alpha=0.12, zorder=1,
                    label="finestra d'attacco" if yi == y[0] else None)
        fine = max(b for _, b in e.fasi.values()) - rif
        estremo_dx = max(estremo_dx, fine)
        aperto = None
        for a in sorted(e.allarmi, key=lambda a: a["t"]):
            t = float(a["t"]) - rif
            if a.get("tipo") == "apertura":
                aperto = t
            elif a.get("tipo") == "chiusura" and aperto is not None:
                ax.plot([aperto, t], [yi, yi], color=SERIE[0], linewidth=4,
                        solid_capstyle="round", zorder=3)
                aperto = None
            elif a.get("tipo") == "primo-segnale":
                ax.plot([t], [yi], marker="|", markersize=7, color=TENUE, zorder=2)
        if aperto is not None:
            ax.plot([aperto, fine], [yi, yi], color=SERIE[0], linewidth=4,
                    solid_capstyle="round", zorder=3)
    ax.plot([], [], color=SERIE[0], linewidth=4, label="allarme aperto")
    ax.plot([], [], marker="|", linestyle="none", markersize=7, color=TENUE,
            label="superamento di soglia di un rivelatore")
    ax.set_yticks(y, [e.scenario for e in righe])
    ax.set_xlim(estremo_sx, estremo_dx + 20)
    ax.set_xlabel("secondi dall'inizio dell'attacco (o della rilevazione)")
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower right", bbox_to_anchor=(1.0, 1.0), ncol=3)
    _titolo(ax, "Cronologia degli allarmi", f"{nome_serie} - una riga per esecuzione")
    return _salva(fig, uscita, "cronologia")


def figura_osservatore(esecuzioni: list[Esecuzione], uscita: Path, nome_serie: str) -> str | None:
    plt = _pyplot()
    dati = []
    for e in esecuzioni:
        persi = (e.metriche.get("osservatore") or {}).get("pacchetti_persi")
        quota = (e.onnisciente.get("confronto") or {}).get("quota_vista_dal_satellite")
        if persi is not None or quota:
            dati.append((e, persi, quota))
    if not dati:
        return None
    fig, assi = plt.subplots(1, 2, figsize=(10, 0.3 * len(dati) + 1.8), sharey=True,
                             gridspec_kw={"wspace": 0.08})
    y = list(range(len(dati)))[::-1]
    persi = [p or 0 for _, p, _ in dati]
    assi[0].barh(y, persi, height=0.55, color=SERIE[0])
    for yi, p in zip(y, persi):
        if p:
            assi[0].text(p + max(persi) * 0.02, yi, f"{p}", va="center", fontsize=8,
                         color=SECONDARIO)
    assi[0].set_xlabel("pacchetti persi dall'osservatore")
    assi[0].set_xlim(0, max(persi + [1]) * 1.3)
    quote = [(yi, q) for yi, (_, _, q) in zip(y, dati) if q]
    if quote:
        _punti(assi[1], [q for _, q in quote], [yi for yi, _ in quote], SERIE[0])
        assi[1].set_xlim(min(0.9, min(q for _, q in quote) - 0.01), 1.01)
    assi[1].set_xlabel("comandi nella vista del satellite / sul filo")
    for ax in assi:
        ax.grid(axis="y", visible=False)
    assi[0].set_yticks(y, [e.scenario for e, _, _ in dati])
    _titolo_figura(fig, "Tenuta della catena di misura",
                   f"{nome_serie} - esecuzioni con pacchetti persi non valide")
    _virgola(*assi)
    return _salva(fig, uscita, "osservatore")


def figura_banco(esecuzioni: list[Esecuzione], uscita: Path, nome_serie: str) -> str | None:
    plt = _pyplot()
    dati = [(e, e.metriche.get("banco") or {}) for e in esecuzioni]
    dati = [(e, b) for e, b in dati if b.get("laboratori_accesi_max") is not None
            or b.get("nodo_ids_frenato_s") is not None]
    if not dati:
        return None
    campi = (("laboratori_accesi_max", "laboratori accesi in contemporanea (massimo)"),
             ("carico_1min_max", "carico della macchina (massimo, 1 min)"),
             ("nodo_ids_frenato_s", "secondi di rallentamento del nodo dell'IDS"))
    fig, assi = plt.subplots(1, 3, figsize=(11, 0.3 * len(dati) + 1.8), sharey=True,
                             gridspec_kw={"wspace": 0.1})
    y = list(range(len(dati)))[::-1]
    for ax, (campo, etichetta) in zip(assi, campi):
        valori = [(yi, b.get(campo)) for yi, (_, b) in zip(y, dati) if b.get(campo) is not None]
        if valori:
            ax.barh([yi for yi, _ in valori], [v for _, v in valori], height=0.55, color=SERIE[0])
        ax.set_xlabel(etichetta)
        ax.set_xlim(left=0)
        ax.grid(axis="y", visible=False)
    assi[0].set_yticks(y, [e.scenario for e, _ in dati])
    _titolo_figura(fig, "Condizioni del banco per esecuzione", nome_serie)
    _virgola(*assi)
    return _salva(fig, uscita, "banco")


COLONNE = (("scenario", "scenario"), ("run_id", "esecuzione"), ("punto", "dispiegamento"),
           ("esito", "esito"), ("latenza", "latenza s"), ("primo", "primo rivelatore"),
           ("fp", "falsi positivi"), ("fp_h", "FP all'ora"), ("quota", "quota in allarme"),
           ("servizio", "servizio"), ("persi", "pacchetti persi"), ("cpu", "CPU %"),
           ("rss", "RSS MB"), ("generazione", "generazione"), ("parallelo", "in parallelo"),
           ("chi", "identificazione"), ("dal_invio", "latenza dal 1° invio s"))


def identificazione_di(e: Esecuzione) -> str | None:
    if not e.con_attacco:
        return None
    if e.metriche.get("identificazione"):
        return e.metriche["identificazione"]
    if "attacco" not in e.fasi:
        return None
    from analysis.metrics import identificazione
    return identificazione(e.allarmi, e.fasi["attacco"])[0] or None


def latenza_dal_primo_invio(e: Esecuzione) -> float | None:
    if not e.con_attacco or latenza(e) is None:
        return None
    if e.metriche.get("latenza_dal_primo_invio_s") is not None:
        return e.metriche["latenza_dal_primo_invio_s"]
    from analysis.metrics import primo_invio
    invio, _ = primo_invio(e.cartella, e.fasi["attacco"][0])
    return None if invio is None else round(latenza(e) - invio, 3)


def riga_tabella(e: Esecuzione) -> dict[str, Any]:
    m = e.metriche
    pf = primi_in_finestra(e)
    primo = min(pf, key=pf.get) if pf else None
    costo = m.get("costo") or {}
    return {
        "scenario": e.scenario, "run_id": e.run_id,
        "punto": DISPIEGAMENTI.get(e.punto, e.punto),
        "esito": esito(e) if e.con_attacco else "senza attacco",
        "chi": identificazione_di(e), "dal_invio": latenza_dal_primo_invio(e),
        "latenza": latenza(e), "primo": NOMI_RIVELATORI.get(primo, primo) if primo else None,
        "fp": m.get("falsi_positivi"), "fp_h": m.get("falsi_positivi_per_ora"),
        "quota": m.get("quota_in_allarme"), "servizio": servizio(e),
        "persi": (m.get("osservatore") or {}).get("pacchetti_persi"),
        "cpu": costo.get("cpu_pct_medio"), "rss": costo.get("rss_mb_massimo"),
        "generazione": m.get("generazione"),
        "parallelo": (m.get("banco") or {}).get("in_parallelo"),
    }


def scrivi_tabelle(esecuzioni: list[Esecuzione], uscita: Path) -> None:
    uscita.mkdir(parents=True, exist_ok=True)
    righe = [riga_tabella(e) for e in esecuzioni]
    with open(uscita / "tabella.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow([t for _, t in COLONNE])
        for r in righe:
            w.writerow(["" if r[k] is None else r[k] for k, _ in COLONNE])
    def cella(v: Any) -> str:
        if v is None:
            return "-"
        if isinstance(v, bool):
            return "sì" if v else "no"
        if isinstance(v, float):
            return numero(v, 2 if abs(v) < 10 else 1)
        return str(v)
    testa = "| " + " | ".join(t for _, t in COLONNE) + " |"
    linea = "|" + "---|" * len(COLONNE)
    corpo = ["| " + " | ".join(cella(r[k]) for k, _ in COLONNE) + " |" for r in righe]
    (uscita / "tabella.md").write_text("\n".join([testa, linea, *corpo]) + "\n", encoding="utf-8")


DIDASCALIE = {
    "latenze.png": "Latenza di rilevazione per scenario. Croce: non rilevato; "
                   "cerchio vuoto: già in allarme.",
    "primo-rivelatore.png": "Primo superamento di soglia per rivelatore; in grassetto il primo.",
    "falsi-positivi.png": "Falsi positivi all'ora e segnali nelle aperture fuori finestra.",
    "costo-ids.png": "CPU media e memoria massima dell'IDS per esecuzione.",
    "servizio.png": "Quota del servizio legittimo mantenuta durante la finestra d'attacco.",
    "cronologia.png": "Allarmi e superamenti di soglia, una riga per esecuzione.",
    "osservatore.png": "Pacchetti persi dalla cattura e comandi registrati dal satellite.",
    "banco.png": "Laboratori in parallelo, carico della macchina e rallentamento dell'IDS.",
}


def grafici_serie(cartella: str | Path, uscita: str | Path | None = None,
                  nome: str | None = None) -> list[str]:
    cartella = Path(cartella)
    uscita = Path(uscita) if uscita else cartella / "grafici"
    nome = nome or cartella.name
    esecuzioni = carica_serie(cartella)
    if not esecuzioni:
        return []
    figure = []
    for funzione in (figura_latenze, figura_primo_rivelatore, figura_falsi_positivi,
                     figura_costo, figura_servizio, figura_cronologia, figura_osservatore,
                     figura_banco):
        try:
            f = funzione(esecuzioni, uscita, nome)
        except Exception as errore:
            print(f"grafico {funzione.__name__} non riuscito per {nome}: {errore}")
            f = None
        if f:
            figure.append(f)
    scrivi_tabelle(esecuzioni, uscita)
    scrivi_indice(uscita, nome, figure, riassunto(esecuzioni))
    return figure


def scrivi_indice(uscita: Path, nome: str, figure: list[str], r: dict[str, Any]) -> None:
    righe = [f"# Grafici: {nome}", "",
             f"- esecuzioni: {r['esecuzioni']}, di cui {r['attacchi']} con attacco;",
             f"- attacchi rilevati: {r['rilevati']} su {r['attacchi']}"
             + (f" ({r['gia_in_allarme']} già in allarme all'apertura)" if r["gia_in_allarme"] else "")
             + ";",
             f"- latenza mediana {numero(r['latenza_mediana_s'])} s, massima "
             f"{numero(r['latenza_massima_s'])} s;",
             f"- falsi positivi: {r['falsi_positivi']}, "
             f"{numero(r['falsi_positivi_per_ora'])} all'ora di esposizione;"]
    if r["cpu_pct_medio"]:
        righe.append(f"- costo dell'IDS: CPU media fra {numero(r['cpu_pct_medio'][0], 2)} e "
                     f"{numero(r['cpu_pct_medio'][1], 2)}%, memoria massima fino a "
                     f"{numero(r['rss_mb_massimo'][1])} MB;")
    righe += [f"- generazione: {', '.join(r['generazioni'])}.", "",
              "Valori completi in `tabella.md` e `tabella.csv`.", ""]
    for f in figure:
        righe += [f"## {DIDASCALIE.get(f, f)}", "", f"![{f}]({f})", ""]
    (uscita / "README.md").write_text("\n".join(righe), encoding="utf-8")


def grafici_confronto(a: str | Path, b: str | Path, nomi: tuple[str, str],
                      uscita: str | Path) -> list[str]:
    plt = _pyplot()
    uscita = Path(uscita)
    sa, sb = carica_serie(a), carica_serie(b)
    if not sa or not sb:
        return []
    figure = []

    def per_scenario(serie: list[Esecuzione]) -> dict[str, list[Esecuzione]]:
        d: dict[str, list[Esecuzione]] = {}
        for e in serie:
            if e.con_attacco:
                d.setdefault(e.scenario_base, []).append(e)
        return d
    pa, pb = per_scenario(sa), per_scenario(sb)
    comuni = sorted(set(pa) & set(pb), key=lambda s: statistics.median(
        [latenza(e) or 1000 for e in pa[s]]))
    if comuni:
        fig, ax = plt.subplots(figsize=(8, 0.34 * len(comuni) + 1.8))
        y = list(range(len(comuni)))[::-1]
        massimo = 1000.0
        def mediana(elenco: list[Esecuzione]) -> tuple[float, str]:
            valide = [latenza(e) for e in elenco
                      if e.metriche.get("rilevato") and latenza(e) is not None]
            if valide:
                return statistics.median(valide), "rilevato"
            if any(e.metriche.get("gia_in_allarme") for e in elenco):
                return massimo, "già in allarme"
            return massimo, "mancato"
        etichettati = set()
        for yi, s in zip(y, comuni):
            (la, ea), (lb, eb) = mediana(pa[s]), mediana(pb[s])
            ax.plot([la, lb], [yi, yi], color=ASSE, linewidth=1.5, zorder=1)
            for valore, stato, colore, nome in ((la, ea, SERIE[0], nomi[0]),
                                                (lb, eb, SERIE[1], nomi[1])):
                if stato == "mancato":
                    ax.scatter([massimo], [yi], marker="x", s=46, color=STATO["mancato"],
                               linewidths=2, zorder=3)
                elif stato == "già in allarme":
                    _punti(ax, [massimo], [yi], colore, vuoto=True)
                else:
                    _punti(ax, [valore], [yi], colore, nome if nome not in etichettati else None)
                    etichettati.add(nome)
        ax.set_xscale("log")
        ax.set_xlim(0.2, massimo * 2)
        ax.set_xticks([0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500],
                      ["0,5", "1", "2", "5", "10", "20", "50", "100", "200", "500"])
        ax.set_yticks(y, comuni)
        ax.set_xlabel("latenza di rilevazione, s (log); croce: non rilevato; "
                      "cerchio: già in allarme")
        ax.grid(axis="y", visible=False)
        ax.legend(loc="lower right", bbox_to_anchor=(1.0, 1.0), ncol=2)
        _titolo(ax, f"Latenza di rilevazione: {nomi[0]} e {nomi[1]}",
                "per scenario; mediana delle esecuzioni dello stesso scenario")
        figure.append(_salva(fig, uscita, "confronto-latenze"))

    ra, rb = riassunto(sa), riassunto(sb)
    misure = (
        ("attacchi rilevati (%)", 100 * ra["rilevati"] / max(1, ra["attacchi"]),
         100 * rb["rilevati"] / max(1, rb["attacchi"]), 0),
        ("latenza mediana (s)", ra["latenza_mediana_s"], rb["latenza_mediana_s"], 1),
        ("falsi positivi all'ora", ra["falsi_positivi_per_ora"], rb["falsi_positivi_per_ora"], 1),
        ("CPU massima dell'IDS (%)", (ra["cpu_pct_medio"] or (None, None))[1],
         (rb["cpu_pct_medio"] or (None, None))[1], 2),
        ("memoria massima (MB)", (ra["rss_mb_massimo"] or (None, None))[1],
         (rb["rss_mb_massimo"] or (None, None))[1], 1),
    )
    fig, assi = plt.subplots(1, len(misure), figsize=(13, 2.4), gridspec_kw={"wspace": 0.6})
    for ax, (titolo, va, vb, cifre) in zip(assi, misure):
        valori = [v if v is not None else 0 for v in (va, vb)]
        ax.bar([0, 1], valori, width=0.55, color=SERIE[:2])
        for x, v, grezzo in zip((0, 1), valori, (va, vb)):
            ax.text(x, v, numero(grezzo, cifre), ha="center", va="bottom", fontsize=8.5,
                    color=INCHIOSTRO)
        ax.set_xticks([0, 1], list(nomi))
        ax.set_title(titolo, loc="left", fontsize=9)
        ax.set_ylim(0, max(valori + [1]) * 1.25)
        ax.grid(axis="x", visible=False)
        ax.tick_params(axis="y", labelsize=7.5)
        _virgola(ax, asse="y")
    fig.suptitle(f"{nomi[0]} e {nomi[1]}: riepilogo delle serie", x=0.125, ha="left",
                 fontsize=11, fontweight="bold", y=1.08)
    figure.append(_salva(fig, uscita, "confronto-riepilogo"))
    righe = [f"# Confronto: {nomi[0]} e {nomi[1]}", "",
             f"- {nomi[0]}: `{Path(a).name}`", f"- {nomi[1]}: `{Path(b).name}`", "",
             "| misura | " + " | ".join(nomi) + " |", "|---|---|---|"]
    for titolo, va, vb, cifre in misure:
        righe.append(f"| {titolo} | {numero(va, cifre)} | {numero(vb, cifre)} |")
    righe.append("")
    for f in figure:
        righe += [f"![{f}]({f})", ""]
    (uscita / "README.md").write_text("\n".join(righe), encoding="utf-8")
    return figure


def grafici_variabilita(cartelle: list[str | Path], uscita: str | Path,
                        nome: str = "variabilità fra esecuzioni") -> list[str]:
    plt = _pyplot()
    uscita = Path(uscita)
    per: dict[str, list[float]] = {}
    mancati: dict[str, int] = {}
    esecuzioni = [e for c in cartelle for e in carica_serie(c) if e.con_attacco]
    distingui = len({e.trasporto for e in esecuzioni} - {"", "?"}) > 1
    for e in esecuzioni:
        chiave = e.scenario_con(distingui)
        lat = latenza(e)
        if e.metriche.get("rilevato") and lat is not None:
            per.setdefault(chiave, []).append(lat)
        else:
            mancati[chiave] = mancati.get(chiave, 0) + 1
    scenari = sorted([s for s in per if len(per[s]) >= 2], key=lambda s: statistics.median(per[s]))
    if not scenari:
        return []
    fig, ax = plt.subplots(figsize=(8, 0.34 * len(scenari) + 1.8))
    y = list(range(len(scenari)))[::-1]
    for yi, s in zip(y, scenari):
        v = per[s]
        ax.plot([min(v), max(v)], [yi, yi], color=ASSE, linewidth=1.5, zorder=1)
        _punti(ax, v, [yi] * len(v), SERIE[0])
        m = statistics.median(v)
        ax.plot([m, m], [yi - 0.3, yi + 0.3], color=INCHIOSTRO, linewidth=2, zorder=4)
        ax.text(max(v) * 1.2, yi, f"n={len(v)}, {numero(min(v))}-{numero(max(v))} s"
                + (f", {mancati[s]} non rilevati" if mancati.get(s) else ""),
                va="center", fontsize=8, color=SECONDARIO)
    ax.set_xscale("log")
    ax.set_xlim(0.2, 3000)
    ax.set_xticks([0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500],
                  ["0,5", "1", "2", "5", "10", "20", "50", "100", "200", "500"])
    ax.set_yticks(y, scenari)
    ax.set_xlabel("latenza di rilevazione, secondi (scala logaritmica); trattino nero: "
                  "mediana")
    ax.grid(axis="y", visible=False)
    _titolo(ax, "Variabilità della latenza fra esecuzioni dello stesso scenario", nome)
    figura = _salva(fig, uscita, "variabilita-latenze")
    with open(uscita / "variabilita.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["scenario", "n", "mediana_s", "min_s", "max_s", "non_rilevati"])
        for s in scenari:
            v = per[s]
            w.writerow([s, len(v), statistics.median(v), min(v), max(v), mancati.get(s, 0)])
    return [figura]


def grafici_taratura(cartella: str | Path, uscita: str | Path) -> list[str]:
    plt = _pyplot()
    cartella, uscita = Path(cartella), Path(uscita)
    curve: dict[str, dict[str, list[tuple[float, float]]]] = {}
    for f in sorted(cartella.glob("*.json")):
        try:
            dati = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for t in dati if isinstance(dati, list) else [dati]:
            for parametro, punti in (t.get("curve") or {}).items():
                curve.setdefault(parametro, {})[t.get("esecuzione", f.stem)] = [
                    (p["valore"], p["allarmi_per_ora"]) for p in punti]
    if not curve:
        return []
    colori = ("#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300")
    fig, assi = plt.subplots(1, len(curve), figsize=(4 * len(curve), 3), squeeze=False,
                             gridspec_kw={"wspace": 0.3})
    for ax, (parametro, perese) in zip(assi[0], sorted(curve.items())):
        for k, (ese, punti) in enumerate(sorted(perese.items())[:len(colori)]):
            ax.plot([x for x, _ in punti], [v for _, v in punti], color=colori[k],
                    linewidth=2, marker="o", markersize=4, label=ese)
        ax.set_title(parametro, loc="left", fontsize=9.5)
        ax.set_ylabel("allarmi all'ora")
        ax.set_ylim(bottom=0)
    assi[0][-1].legend(loc="upper left", bbox_to_anchor=(1.02, 1), fontsize=7.5)
    fig.suptitle("Taratura: allarmi all'ora senza attacco per parametro",
                 x=0.125, ha="left", fontsize=11, fontweight="bold", y=1.05)
    return [_salva(fig, uscita, "taratura")]


class TipoGrafico(StrEnum):
    SERIE = "serie"
    CONFRONTO = "confronto"
    VARIABILITA = "variabilita"
    TARATURA = "taratura"
    TUTTO = "tutto"


def grafici_tutto(radice: str | Path) -> list[Path]:
    radice = Path(radice)
    fatte = []
    for d in sorted(p for p in radice.iterdir() if p.is_dir()):
        if any((x / "metriche.json").exists() for x in d.iterdir() if x.is_dir()):
            if grafici_serie(d):
                fatte.append(d / "grafici")
            if (d / "taratura").is_dir():
                grafici_taratura(d / "taratura", d / "grafici")
    elenco = radice / "confronti-grafici.json"
    if elenco.exists():
        for c in json.loads(elenco.read_text(encoding="utf-8")):
            uscita = radice / c["uscita"]
            if c["tipo"] == TipoGrafico.CONFRONTO:
                grafici_confronto(radice / c["a"], radice / c["b"], tuple(c["nomi"]), uscita)
            elif c["tipo"] == TipoGrafico.VARIABILITA:
                grafici_variabilita([radice / x for x in c["serie"]], uscita, c.get("nome", ""))
            fatte.append(uscita)
    indice = radice / "grafici" / "README.md"
    indice.parent.mkdir(parents=True, exist_ok=True)
    righe = ["# Grafici dei risultati", "",
             "Generati con `python3 -m analysis.grafici tutto risultati/`.", ""]
    for g in fatte:
        relativo = g.relative_to(radice)
        su = Path("..") / relativo if relativo.parts[0] != "grafici" else Path(*relativo.parts[1:])
        righe.append(f"- [{relativo.parent if relativo.name == 'grafici' else relativo.name}]"
                     f"({su.as_posix()}/README.md)")
    indice.write_text("\n".join(righe) + "\n", encoding="utf-8")
    return fatte


def main() -> None:
    ap = argparse.ArgumentParser(description="Grafici delle statistiche del banco")
    sotto = ap.add_subparsers(dest="cosa", required=True)
    s = sotto.add_parser(TipoGrafico.SERIE.value, help="grafici di una serie")
    s.add_argument("cartella", help="cartella della serie")
    s.add_argument("--uscita", default=None, help="cartella dei grafici")
    s.add_argument("--nome", default=None, help="nome della serie nei titoli")
    c = sotto.add_parser(TipoGrafico.CONFRONTO.value, help="confronto fra 2 serie")
    c.add_argument("a", help="cartella della prima serie")
    c.add_argument("b", help="cartella della seconda serie")
    c.add_argument("--nomi", nargs=2, required=True, help="nomi delle 2 serie nei titoli")
    c.add_argument("--uscita", required=True, help="cartella dei grafici")
    v = sotto.add_parser(TipoGrafico.VARIABILITA.value, help="variabilità della latenza fra esecuzioni")
    v.add_argument("cartelle", nargs="+", help="cartelle delle serie")
    v.add_argument("--uscita", required=True, help="cartella dei grafici")
    v.add_argument("--nome", default="variabilità fra esecuzioni", help="titolo del grafico")
    t = sotto.add_parser(TipoGrafico.TARATURA.value, help="curve di taratura")
    t.add_argument("cartella", help="cartella con le curve di taratura")
    t.add_argument("--uscita", required=True, help="cartella dei grafici")
    u = sotto.add_parser(TipoGrafico.TUTTO.value, help="grafici di tutte le serie")
    u.add_argument("radice", help="cartella dei risultati")
    args = ap.parse_args()
    match args.cosa:
        case TipoGrafico.SERIE:
            print("\n".join(grafici_serie(args.cartella, args.uscita, args.nome)))
        case TipoGrafico.CONFRONTO:
            print("\n".join(grafici_confronto(args.a, args.b, tuple(args.nomi), args.uscita)))
        case TipoGrafico.VARIABILITA:
            print("\n".join(grafici_variabilita(args.cartelle, args.uscita, args.nome)))
        case TipoGrafico.TARATURA:
            print("\n".join(grafici_taratura(args.cartella, args.uscita)))
        case _:
            print("\n".join(str(p) for p in grafici_tutto(args.radice)))


if __name__ == "__main__":
    main()
