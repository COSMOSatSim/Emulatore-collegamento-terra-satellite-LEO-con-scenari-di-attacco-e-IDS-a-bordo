from __future__ import annotations

import argparse
import json
import struct
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

from common.protocol import IDENTIFICATORI_NOTI, Riassemblatore, decodifica_comando
from sensor.wiretap import OrdineTcp, analizza_telaio

MAGIE: dict[bytes, tuple[str, int]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
LINKTYPE_ETHERNET = 1


def leggi_pcap(percorso: str | Path) -> Iterator[tuple[float, bytes]]:
    percorso = Path(percorso)
    with percorso.open("rb") as f:
        magia = f.read(4)
        if magia not in MAGIE:
            raise ValueError(f"file non pcap: {percorso}")
        ordine, divisore = MAGIE[magia]
        resto = f.read(20)
        if len(resto) < 20:
            return
        linktype = struct.unpack(ordine + "I", resto[16:20])[0]
        if linktype != LINKTYPE_ETHERNET:
            raise ValueError(f"livello di collegamento non Ethernet: {linktype}")
        while True:
            intestazione = f.read(16)
            if len(intestazione) < 16:
                return
            sec, frazione, catturati, _originali = struct.unpack(
                ordine + "IIII", intestazione)
            telaio = f.read(catturati)
            if len(telaio) < catturati:
                return
            yield sec + frazione / divisore, telaio


def riassumi(percorso: str | Path, porta_servizio: int = 5000) -> dict[str, Any]:
    telai = 0
    non_ip = 0
    origini: Counter[str] = Counter()
    syn: Counter[str] = Counter()
    comandi: Counter[str] = Counter()
    per_origine: Counter[str] = Counter()
    flussi: dict[str, Riassemblatore] = {}
    ordini: dict[str, OrdineTcp] = {}
    primo = ultimo = None

    for t, telaio in leggi_pcap(percorso):
        telai += 1
        primo = t if primo is None else primo
        ultimo = t
        seg = analizza_telaio(telaio)
        if seg is None:
            non_ip += 1
            continue
        origini[seg.ip_mittente] += 1
        if seg.porta_destinatario != porta_servizio:
            continue
        if seg.syn:
            syn[seg.ip_mittente] += 1
            ordini.setdefault(seg.flusso, OrdineTcp()).syn(seg.seq)
        if not seg.carico:
            continue
        r = flussi.setdefault(seg.flusso,
                              Riassemblatore(identificatori=IDENTIFICATORI_NOTI))
        nuovi = ordini.setdefault(seg.flusso, OrdineTcp()).alimenta(seg.seq, seg.carico, t)
        for grezzo in r.alimenta(nuovi) if nuovi else ():
            try:
                tc = decodifica_comando(grezzo)
            except Exception:
                comandi["illeggibile"] += 1
                continue
            comandi[tc.nome] += 1
            per_origine[seg.ip_mittente] += 1

    return {
        "file": str(percorso),
        "telai": telai,
        "telai_non_ip": non_ip,
        "durata_s": round(ultimo - primo, 3) if primo is not None else 0.0,
        "origini": dict(origini.most_common()),
        "aperture_per_origine": dict(syn.most_common()),
        "comandi": dict(comandi.most_common()),
        "comandi_per_origine": dict(per_origine.most_common()),
        "flussi_verso_il_servizio": len(flussi),
    }


def confronta_vista_locale(riassunto: dict[str, Any],
                           vista_satellite: str | Path) -> dict[str, Any]:
    from model.events import APP_COMANDO, leggi_tutto

    locali = sum(1 for ev in leggi_tutto(Path(vista_satellite))
                 if ev.tipo == APP_COMANDO)
    sul_filo = sum(riassunto.get("comandi", {}).values())
    return {
        "comandi_sul_filo": sul_filo,
        "comandi_nella_vista_locale": locali,
        "differenza": sul_filo - locali,
        "quota_vista_dal_satellite": (round(locali / sul_filo, 4)
                                      if sul_filo else None),
    }


def valuta_cartella(radice: str | Path) -> dict[str, Any]:
    radice = Path(radice)
    catture = sorted((radice / "omniscient").rglob("*.pcap"))
    if not catture:
        return {"errore": "nessuna cattura onnisciente nell'esecuzione"}
    riassunto = riassumi(catture[0])
    viste = sorted(list((radice / "local").rglob("satellite.jsonl"))
                   + list((radice / "local").rglob("satellite.jsonl.gz")))
    if viste:
        riassunto["confronto"] = confronta_vista_locale(riassunto, viste[0])
    return riassunto


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Vista onnisciente di una o più esecuzioni")
    ap.add_argument("cartelle", nargs="+", help="cartelle delle esecuzioni")
    args = ap.parse_args()
    print(json.dumps({str(c): valuta_cartella(c) for c in args.cartelle},
                     indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
