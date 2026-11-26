from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

from ids.alarm import AlarmEmitter
from ids.capture import crea_punto_di_cattura
from ids.engine import IdsEngine
from ids.features import FeatureExtractor
from ids.fusion import GIU, SOGLIA, SU, ScoreFusion
from ids.profile import NormalityProfile

GRIGLIA: dict[str, tuple[float, ...]] = {
    "soglia": (0.4, 0.5, 0.6, 0.7, 0.8, 0.9),
    "su": (2, 3, 4, 6, 8, 12),
    "cusum_h": (5.0, 8.0, 12.0, 16.0, 24.0),
}


def _inizio_rilevazione(radice: Path) -> float | None:
    for nome in ("truth/etichette.jsonl", "etichette.jsonl"):
        f = radice / nome
        if not f.exists():
            continue
        for riga in f.read_text(encoding="utf-8").splitlines():
            try:
                v = json.loads(riga)
            except ValueError:
                continue
            if (v.get("etichetta") == "fase"
                    and v["dati"].get("nome") == "avvio"
                    and v["dati"].get("evento") == "fine"):
                return float(v["t"])
    return None


def _vista_e_profilo(radice: Path) -> tuple[Path, Path, str]:
    viste = sorted(list((radice / "local").rglob("*.jsonl"))
                   + list((radice / "local").rglob("*.jsonl.gz")))
    vista = next((v for v in viste
                  if v.name.removesuffix(".gz") in ("satellite.jsonl",
                                                    "idsline.jsonl")), None)
    if vista is None:
        raise FileNotFoundError(f"nessuna vista locale in {radice}")
    profili = sorted((radice / "local").rglob("profilo.json"))
    if not profili:
        riusato = radice / "config" / "profilo_riusato.json"
        if riusato.exists():
            profili = [riusato]
    if not profili:
        from analysis.ablazione import profilo_di
        try:
            profili = [profilo_di(radice, [radice.parent])]
        except (FileNotFoundError, KeyError):
            pass
    if not profili:
        raise FileNotFoundError(
            f"nessun profilo per {radice} in local/, config/ o nella serie")
    punto = "in-linea" if vista.name == "idsline.jsonl" else "co-residente"
    return vista, profili[0], punto


def _conta_allarmi(vista: Path, profilo_file: Path, punto: str, *,
                   soglia: float = SOGLIA, su: int = SU, giu: int = GIU,
                   cusum_h: float | None = None,
                   da: float | None = None) -> dict[str, Any]:
    import ids.detectors as rivelatori

    vecchio = rivelatori.CUSUM_H
    if cusum_h is not None:
        rivelatori.CUSUM_H = cusum_h
        rivelatori.CUSUM_TETTO = cusum_h * 1.5
    try:
        cattura = crea_punto_di_cattura(punto, vista)
        profilo = NormalityProfile.carica(profilo_file)
        profilo.fissa()
        motore = IdsEngine(cattura, profilo, AlarmEmitter([]),
                           estrattore=FeatureExtractor(),
                           fusione=ScoreFusion(soglia=soglia, su=su, giu=giu))
        motore.passa_a_rilevazione()
        eventi = [e for e in cattura.nuovi() if da is None or e.t >= da]
        motore.estrattore.alimenta(eventi)
        finestre = motore.estrattore.finestre_pronte()
        for fv in finestre:
            motore.finestre_viste += 1
            motore._valuta(fv)
        alzati = [d for d in motore.decisioni if d.appena_alzato]
        durata = (finestre[-1].t - finestre[0].t) if len(finestre) > 1 else 0.0
        return {
            "allarmi": len(alzati),
            "finestre": len(finestre),
            "durata_s": round(durata, 1),
            "allarmi_per_ora": round(len(alzati) / (durata / 3600.0), 2)
            if durata > 60 else None,
            "quota_finestre_sopra_soglia": round(
                sum(1 for d in motore.decisioni if d.punteggio >= soglia)
                / max(len(motore.decisioni), 1), 4),
        }
    finally:
        rivelatori.CUSUM_H = vecchio
        rivelatori.CUSUM_TETTO = vecchio * 1.5


def esplora(radice: str | Path,
            parametri: Iterable[str] = ("soglia", "su", "cusum_h")) -> dict[str, Any]:
    radice = Path(radice)
    vista, profilo, punto = _vista_e_profilo(radice)
    da = _inizio_rilevazione(radice)
    base = {"soglia": SOGLIA, "su": SU, "giu": GIU, "da": da}
    risultato: dict[str, Any] = {
        "esecuzione": radice.name, "punto_di_cattura": punto,
        "transitorio_scartato": da is not None,
        "riferimento": _conta_allarmi(vista, profilo, punto, **base),
        "curve": {},
    }
    if da is None:
        risultato["ATTENZIONE"] = ("verità di riferimento assente: "
                                   "transitorio d'avvio non scartato")
    for nome in parametri:
        if nome not in GRIGLIA:
            continue
        curva = []
        for valore in GRIGLIA[nome]:
            kw = dict(base)
            if nome == "cusum_h":
                kw["cusum_h"] = float(valore)
            else:
                kw[nome] = type(base[nome])(valore)
            curva.append({"valore": valore, **_conta_allarmi(vista, profilo, punto, **kw)})
        risultato["curve"][nome] = curva
    return risultato


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Falsi positivi al variare dei parametri")
    ap.add_argument("cartelle", nargs="+",
                    help="cartelle di esecuzioni senza attacco, come S0")
    ap.add_argument("--parametro", action="append", default=None,
                    choices=sorted(GRIGLIA),
                    help="parametro da variare, ripetibile; tutti se omesso")
    args = ap.parse_args()
    parametri = args.parametro or sorted(GRIGLIA)
    print(json.dumps([esplora(c, parametri) for c in args.cartelle],
                     indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
