from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from model.events import APP_COMANDO, APP_SESSIONE, Event, leggi_tutto

ATTACCANTE = "10.0.0.40"


def _eventi(percorso: Path) -> Iterable[Event]:
    return leggi_tutto(percorso)


def misura(vista_satellite: str | Path, fasi: dict[str, tuple[float, float]],
           attaccante: str = ATTACCANTE) -> dict[str, Any]:
    conteggi: dict[str, int] = {nome: 0 for nome in fasi}
    sessioni: dict[str, int] = {nome: 0 for nome in fasi}
    rifiutati: dict[str, int] = {nome: 0 for nome in fasi}
    for ev in _eventi(Path(vista_satellite)):
        if ev.tipo not in (APP_COMANDO, APP_SESSIONE):
            continue
        if str(ev.dati.get("peer", "")).startswith(attaccante):
            continue
        for nome, (inizio, fine) in fasi.items():
            if not (inizio <= ev.t <= fine):
                continue
            if ev.tipo == APP_COMANDO:
                conteggi[nome] += 1
                if ev.dati.get("esito") not in (None, "accettato", "osservato"):
                    rifiutati[nome] += 1
            elif ev.dati.get("evento") == "apertura":
                sessioni[nome] += 1

    risultato: dict[str, Any] = {"per_fase": {}}
    for nome, (inizio, fine) in fasi.items():
        durata = max(fine - inizio, 1e-9)
        risultato["per_fase"][nome] = {
            "durata_s": round(durata, 1),
            "comandi_legittimi": conteggi[nome],
            "comandi_al_secondo": round(conteggi[nome] / durata, 4),
            "comandi_non_accettati": rifiutati[nome],
            "aperture_legittime": sessioni[nome],
        }

    nominale = risultato["per_fase"].get("nominale", {}).get("comandi_al_secondo")
    attacco = risultato["per_fase"].get("attacco", {}).get("comandi_al_secondo")
    if attacco is None:
        risultato["servizio_mantenuto"] = None
        risultato["nota"] = "nessuna finestra d'attacco: rapporto non calcolabile"
    elif nominale:
        risultato["servizio_mantenuto"] = round(attacco / nominale, 4)
        risultato["nota"] = "quota del servizio nominale nell'attacco (1 = invariato)"
    else:
        risultato["servizio_mantenuto"] = None
        risultato["nota"] = "fase nominale assente, vedi servizio_mantenuto_su_quiete"
        quiete = risultato["per_fase"].get("quiete", {}).get("comandi_al_secondo")
        if quiete:
            risultato["servizio_mantenuto_su_quiete"] = round(attacco / quiete, 4)
    return risultato


def _percentile(valori: list[float], quota: float) -> float | None:
    if not valori:
        return None
    ordinati = sorted(valori)
    return ordinati[min(len(ordinati) - 1, int(round(quota * (len(ordinati) - 1))))]


def latenze_legittime(viste_stazioni: Iterable[Path],
                      fasi: dict[str, tuple[float, float]]) -> dict[str, Any]:
    per_fase: dict[str, list[float]] = {nome: [] for nome in fasi}
    senza: dict[str, int] = {nome: 0 for nome in fasi}
    for vista in viste_stazioni:
        for ev in _eventi(vista):
            if ev.tipo != APP_COMANDO or ev.dati.get("ruolo") != "ground":
                continue
            istante = float(ev.dati.get("inviato", ev.t))
            for nome, (inizio, fine) in fasi.items():
                if inizio <= istante <= fine:
                    if ev.dati.get("latenza_ms") is None:
                        if ev.dati.get("esito") == "senza-risposta":
                            senza[nome] += 1
                    else:
                        per_fase[nome].append(float(ev.dati["latenza_ms"]))
    risultato: dict[str, Any] = {}
    for nome, valori in per_fase.items():
        if not valori and not senza[nome]:
            continue
        risultato[nome] = {
            "comandi": len(valori),
            "senza_risposta": senza[nome],
            "mediana_ms": round(_percentile(valori, 0.5), 3) if valori else None,
            "p95_ms": round(_percentile(valori, 0.95), 3) if valori else None,
        }
    riferimento = risultato.get("nominale") or risultato.get("quiete")
    attacco = risultato.get("attacco")
    if riferimento and attacco and riferimento.get("p95_ms") and attacco.get("p95_ms"):
        risultato["p95_attacco_su_riferimento"] = round(
            attacco["p95_ms"] / riferimento["p95_ms"], 3)
    return risultato


def fasi_da_etichette(etichette: list[dict]) -> dict[str, tuple[float, float]]:
    aperte: dict[str, float] = {}
    fasi: dict[str, tuple[float, float]] = {}
    for v in etichette:
        if v.get("etichetta") != "fase":
            continue
        nome = v["dati"].get("nome")
        if v["dati"].get("evento") == "inizio":
            aperte[nome] = float(v["t"])
        elif v["dati"].get("evento") == "fine" and nome in aperte:
            fasi[nome] = (aperte.pop(nome), float(v["t"]))
    return fasi


def valuta_cartella(radice: str | Path) -> dict[str, Any]:
    radice = Path(radice)
    etichette = []
    f = radice / "truth" / "etichette.jsonl"
    if not f.exists():
        f = radice / "etichette.jsonl"
    if f.exists():
        for riga in f.read_text(encoding="utf-8").splitlines():
            if riga.strip():
                try:
                    etichette.append(json.loads(riga))
                except ValueError:
                    continue
    fasi = fasi_da_etichette(etichette)
    if not fasi:
        return {"errore": "nessuna fase nella verità di riferimento"}
    viste = sorted(list(radice.rglob("satellite.jsonl"))
                   + list(radice.rglob("satellite.jsonl.gz")))
    if not viste:
        return {"errore": "vista locale del satellite assente"}
    risultato = misura(viste[0], fasi)
    stazioni = sorted(v for v in list(radice.rglob("ground*.jsonl"))
                      + list(radice.rglob("ground*.jsonl.gz")))
    latenze = latenze_legittime(stazioni, fasi) if stazioni else {}
    if latenze:
        risultato["latenze_legittime"] = latenze
    return risultato
