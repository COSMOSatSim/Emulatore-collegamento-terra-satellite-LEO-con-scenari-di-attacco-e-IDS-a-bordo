from __future__ import annotations

from typing import Any

GENERAZIONE = "soglie-v17"


def _attesa_fuori_ordine() -> float:
    from sensor.wiretap import OrdineTcp
    return OrdineTcp.ATTESA_MASSIMA_S


def parametri_ids() -> dict[str, Any]:
    from common import identita, visibilita
    from ids import detectors, engine, features, fusion, profile

    return {
        "generazione": GENERAZIONE,
        "fusione": {
            "soglia": fusion.SOGLIA,
            "finestre_per_alzare": fusion.SU,
            "finestre_per_abbassare": fusion.GIU,
            "pesi": dict(fusion.PESI_PREDEFINITI),
            "soglie_rivelatore": dict(fusion.SOGLIE_RIVELATORE),
            "massimi_segnali_annotati": fusion.MASSIMI_SEGNALI,
        },
        "finestre": {
            "breve_s": features.FINESTRA_BREVE,
            "passo_s": features.PASSO,
            "contesto_s": features.FINESTRA_LUNGA,
            "guadagno_di_sondaggio": features.GUADAGNO_SONDAGGIO,
        },
        "volumetrico": {
            "cusum_k": detectors.CUSUM_K,
            "cusum_h": detectors.CUSUM_H,
            "cusum_tetto": detectors.CUSUM_TETTO,
            "cusum_oblio": detectors.CUSUM_OBLIO,
            "deviazioni_massime_per_finestra": detectors.DEVIAZIONI_MASSIME_PER_FINESTRA,
            "soglia_squilibrio": detectors.VolumetricDetector.SOGLIA_SQUILIBRIO,
            "osservate": list(detectors.VolumetricDetector.OSSERVATE),
            "riferimento_collettivo": list(detectors.VolumetricDetector.RIFERIMENTO_COLLETTIVO),
            "campioni_del_serbatoio": profile.Statistica._limite_campioni,
            "scala_riferimento_collettivo": detectors.VolumetricDetector.SCALA_RIFERIMENTO_COLLETTIVO,
            "accumula": "solo la crescita oltre il percentile alto",
        },
        "grandezze_bbr": {
            "solo_se": "non limitata dall'applicazione e fuori dall'avvio",
            "guadagno_avvio": features.GUADAGNO_AVVIO,
            "guadagno_svuotamento": features.GUADAGNO_SVUOTAMENTO,
        },
        "interlocutori": {
            "presenti": "con una sessione aperta",
        },
        "filo": {
            "ritrasmissioni": "scartate per numero di sequenza TCP",
            "attesa_massima_fuori_ordine_s": _attesa_fuori_ordine(),
        },
        "coerenza_identita": {
            "soglia_deviazioni": detectors.IdentityCoherenceDetector.SOGLIA_DEVIAZIONI,
            "finestra_attivita_s": identita.FINESTRA_ATTIVITA,
            "margine_guardia_s": visibilita.MARGINE_GUARDIA,
            "confronti_per_peer": list(detectors.IdentityCoherenceDetector.CONFRONTI),
        },
        "stato_di_bordo": {
            "osservate": ["cpu_pct", "memoria_usata_mb", "processi"],
            "soglia_deviazioni": 3.5,
            "fonte": "cgroup del container",
        },
        "grammatica": {
            "memoria_fuori_catalogo_s": detectors.DialogueGrammarDetector.MEMORIA,
        },
        "profilo": {
            "nominale_dopo_il_transitorio": True,
            "alfa": profile.ALFA,
            "minimo_campioni": profile.MIN_CAMPIONI,
            "percentile_di_riferimento": 0.99,
        },
        "motore": {
            "pausa_fra_primi_segnali_s": engine.PAUSA_SEGNALE,
        },
    }


def differenze(a: dict[str, Any], b: dict[str, Any],
               prefisso: str = "") -> list[str]:
    fuori: list[str] = []
    for chiave in sorted(set(a) | set(b)):
        va, vb = a.get(chiave), b.get(chiave)
        nome = f"{prefisso}{chiave}"
        if isinstance(va, dict) and isinstance(vb, dict):
            fuori += differenze(va, vb, f"{nome}.")
        elif va != vb:
            fuori.append(f"{nome}: {va} contro {vb}")
    return fuori
