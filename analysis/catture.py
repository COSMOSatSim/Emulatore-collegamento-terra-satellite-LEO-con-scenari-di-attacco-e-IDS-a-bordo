from __future__ import annotations

import argparse
import hashlib
import json
import queue
import shutil
import subprocess
import sys
import threading
import time
from enum import StrEnum
from pathlib import Path
from typing import Any, BinaryIO, Callable, Sequence

PARTE_BYTE = 90 * 1024 * 1024

LIVELLO = 19

FINESTRA_LUNGA = 27
BLOCCO = 1024 * 1024
MANIFESTO = "catture.json"


def compressore(livello: int = LIVELLO) -> list[str]:
    return ["nice", "-n", "19", "zstd", f"-{livello}", f"--long={FINESTRA_LUNGA}",
            "-T1", "-q", "-c", "-"]


def decompressore() -> list[str]:
    return ["zstd", "-d", f"--long={FINESTRA_LUNGA}", "-q", "-c", "-"]


def impronta(f: Path) -> str:
    h = hashlib.sha256()
    with open(f, "rb") as sorgente:
        for blocco in iter(lambda: sorgente.read(BLOCCO), b""):
            h.update(blocco)
    return h.hexdigest()


def _spezza(flusso: BinaryIO, destinazione: Path, nome: str,
            parte_byte: int) -> list[dict[str, Any]]:
    parti: list[dict[str, Any]] = []
    indice = 0
    while True:
        h = hashlib.sha256()
        scritti = 0
        percorso = destinazione / f"{nome}.zst.{indice:03d}"
        with open(percorso, "wb") as parte:
            while scritti < parte_byte:
                blocco = flusso.read(min(BLOCCO, parte_byte - scritti))
                if not blocco:
                    break
                parte.write(blocco)
                h.update(blocco)
                scritti += len(blocco)
        if scritti == 0:
            percorso.unlink()
            break
        parti.append({"nome": percorso.name, "byte": scritti, "sha256": h.hexdigest()})
        indice += 1
        if scritti < parte_byte:
            break
    return parti


def comprimi_file(sorgente: Path, destinazione: Path, livello: int = LIVELLO,
                  parte_byte: int = PARTE_BYTE,
                  comando: Sequence[str] | None = None) -> dict[str, Any]:
    destinazione.mkdir(parents=True, exist_ok=True)
    inizio = time.monotonic()
    with open(sorgente, "rb") as ingresso:
        processo = subprocess.Popen(list(comando or compressore(livello)), stdin=ingresso,
                                    stdout=subprocess.PIPE)
        assert processo.stdout is not None
        with processo.stdout as uscita:
            parti = _spezza(uscita, destinazione, sorgente.name, parte_byte)
        esito = processo.wait()
    if esito != 0:
        raise RuntimeError(f"compressore terminato con codice {esito} su {sorgente}")
    originale = sorgente.stat().st_size
    compressi = sum(p["byte"] for p in parti)
    return {
        "nome": sorgente.name,
        "byte": originale,
        "sha256": impronta(sorgente),
        "byte_compressi": compressi,
        "rapporto": round(originale / compressi, 2) if compressi else None,
        "secondi": round(time.monotonic() - inizio, 1),
        "parti": parti,
    }


def catture_di(esecuzione: Path) -> list[Path]:
    if esecuzione.is_file():
        return [esecuzione]
    return sorted(f for f in (esecuzione / "omniscient").glob("*.pcap") if f.is_file())


def comprimi(esecuzione: Path, destinazione: Path, livello: int = LIVELLO,
             parte_byte: int = PARTE_BYTE, cancella: bool = False,
             comando: Sequence[str] | None = None,
             decomando: Sequence[str] | None = None) -> dict[str, Any]:
    catture = catture_di(esecuzione)
    if not catture:
        raise FileNotFoundError(f"nessuna cattura in {esecuzione}")
    destinazione.mkdir(parents=True, exist_ok=True)
    manifesto: dict[str, Any] = {
        "esecuzione": esecuzione.name if esecuzione.is_dir() else esecuzione.stem,
        "formato": f"zstd -{livello} --long={FINESTRA_LUNGA}, parti da {parte_byte} byte",
        "catture": [],
    }
    run = esecuzione / "config" / "run.json"
    if esecuzione.is_dir() and run.exists():
        r = json.loads(run.read_text(encoding="utf-8"))
        manifesto.update({k: r.get(k) for k in ("scenario", "generazione", "commit",
                                                "chiave_profilo") if k in r})
    for c in catture:
        manifesto["catture"].append(comprimi_file(c, destinazione, livello, parte_byte,
                                                  comando))
    (destinazione / MANIFESTO).write_text(json.dumps(manifesto, indent=2, ensure_ascii=False),
                                          encoding="utf-8")
    if cancella:
        for c, voce in zip(catture, manifesto["catture"]):
            if verifica(destinazione, voce["nome"], ricomponendo=True,
                        comando=decomando) == []:
                c.unlink()
    return manifesto


def _manifesto(archivio: Path) -> dict[str, Any]:
    return json.loads((archivio / MANIFESTO).read_text(encoding="utf-8"))


def _voce(archivio: Path, nome: str | None) -> dict[str, Any]:
    voci = _manifesto(archivio)["catture"]
    if nome is None:
        if len(voci) != 1:
            raise ValueError(f"{archivio}: {len(voci)} catture, nome della cattura "
                             f"obbligatorio")
        return voci[0]
    for v in voci:
        if v["nome"] == nome:
            return v
    raise KeyError(f"{nome} assente in {archivio / MANIFESTO}")


def ricomponi(archivio: Path, uscita: Path, nome: str | None = None,
              comando: Sequence[str] | None = None) -> Path:
    voce = _voce(archivio, nome)
    for p in voce["parti"]:
        if impronta(archivio / p["nome"]) != p["sha256"]:
            raise ValueError(f"impronta della parte {p['nome']} diversa da quella "
                             f"registrata")
    with open(uscita, "wb") as destinazione:
        processo = subprocess.Popen(list(comando or decompressore()), stdin=subprocess.PIPE,
                                    stdout=destinazione)
        assert processo.stdin is not None
        for p in voce["parti"]:
            with open(archivio / p["nome"], "rb") as parte:
                shutil.copyfileobj(parte, processo.stdin, BLOCCO)
        processo.stdin.close()
        esito = processo.wait()
    if esito != 0:
        raise RuntimeError(f"decompressore terminato con codice {esito}")
    if impronta(uscita) != voce["sha256"]:
        raise ValueError(f"{uscita} diverso dall'originale")
    return uscita


def verifica(archivio: Path, nome: str | None = None, ricomponendo: bool = False,
             comando: Sequence[str] | None = None) -> list[str]:
    problemi: list[str] = []
    voci = [_voce(archivio, nome)] if nome else _manifesto(archivio)["catture"]
    for v in voci:
        for p in v["parti"]:
            f = archivio / p["nome"]
            if not f.exists():
                problemi.append(f"parte mancante: {p['nome']}")
            elif impronta(f) != p["sha256"]:
                problemi.append(f"impronta della parte {p['nome']} diversa da quella "
                                f"registrata")
        if ricomponendo and not problemi:
            prova = archivio / f".{v['nome']}.verifica"
            try:
                ricomponi(archivio, prova, v["nome"], comando)
            except (RuntimeError, ValueError) as errore:
                problemi.append(str(errore))
            finally:
                prova.unlink(missing_ok=True)
    return problemi


def pilota(sorgente: Path, livelli: Sequence[int], cartella: Path) -> list[dict[str, Any]]:
    risultati = []
    for livello in livelli:
        voce = comprimi_file(sorgente, cartella / f"livello-{livello}", livello)
        risultati.append({"livello": livello, "byte": voce["byte"],
                          "byte_compressi": voce["byte_compressi"],
                          "rapporto": voce["rapporto"], "secondi": voce["secondi"]})
        shutil.rmtree(cartella / f"livello-{livello}")
    return risultati


class CodaCatture:
    def __init__(self, coda: Path, archivio: Path, serie: str, dopo: str | None = None,
                 scrivi: Callable[[str], None] = print, livello: int = LIVELLO,
                 comando: Sequence[str] | None = None,
                 decomando: Sequence[str] | None = None) -> None:
        self.coda = coda
        self.archivio = archivio
        self.serie = serie
        self.dopo = dopo
        self.scrivi = scrivi
        self.livello = livello
        self.comando = comando
        self.decomando = decomando
        self.problemi: list[str] = []
        self._lavori: queue.Queue[str | None] = queue.Queue()
        self._thread = threading.Thread(target=self._lavora, name="catture", daemon=False)
        self._thread.start()

    def accoda(self, radice: Path, run_id: str) -> bool:
        catture = catture_di(radice)
        if not catture:
            return False
        destinazione = self.coda / run_id
        (destinazione / "omniscient").mkdir(parents=True, exist_ok=True)
        for c in catture:
            c.rename(destinazione / "omniscient" / c.name)
        run = radice / "config" / "run.json"
        if run.exists():
            (destinazione / "config").mkdir(exist_ok=True)
            shutil.copy2(run, destinazione / "config" / "run.json")
        self._lavori.put(run_id)
        return True

    def _lavora(self) -> None:
        while True:
            run_id = self._lavori.get()
            if run_id is None:
                return
            sorgente = self.coda / run_id
            uscita = self.archivio / self.serie / run_id
            try:
                m = comprimi(sorgente, uscita, self.livello, cancella=True,
                             comando=self.comando, decomando=self.decomando)
                restano = catture_di(sorgente)
                if restano:
                    self.problemi.append(f"{run_id}: ricomposizione non verificata, "
                                         f"originale conservato in {sorgente}")
                else:
                    shutil.rmtree(sorgente, ignore_errors=True)
                for voce in m["catture"]:
                    self.scrivi(f"cattura {run_id}/{voce['nome']}: x{voce['rapporto']} in "
                                f"{len(voce['parti'])} parti, {voce['secondi']} s")
                if self.dopo:
                    esito = subprocess.run(self.dopo.format(id=run_id, cartella=uscita),
                                           shell=True).returncode
                    if esito != 0:
                        self.problemi.append(f"{run_id}: pubblicazione terminata con "
                                             f"codice {esito}")
            except Exception as errore:
                self.problemi.append(f"{run_id}: {errore}")
            for p in self.problemi:
                self.scrivi(f"problema: {p}")
            self.problemi.clear()

    def aspetta(self) -> None:
        self._lavori.put(None)
        self._thread.join()


class Operazione(StrEnum):
    COMPRIMI = "comprimi"
    RICOMPONI = "ricomponi"
    VERIFICA = "verifica"
    PILOTA = "pilota"


def main(argv: Sequence[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Compressione e divisione delle catture")
    sotto = ap.add_subparsers(dest="azione", required=True)
    c = sotto.add_parser(Operazione.COMPRIMI.value,
                         help="comprime le catture in parti")
    c.add_argument("esecuzione", type=Path, help="cartella dell'esecuzione o file pcap")
    c.add_argument("destinazione", type=Path, help="cartella d'archivio <archivio>/<serie>/<id>")
    c.add_argument("--livello", type=int, default=LIVELLO, help="livello di zstd")
    c.add_argument("--cancella", action="store_true",
                   help="rimuove l'originale dopo la verifica della ricomposizione")
    r = sotto.add_parser(Operazione.RICOMPONI.value, help="riunisce le parti e decomprime")
    r.add_argument("archivio", type=Path, help="cartella d'archivio")
    r.add_argument("uscita", type=Path, help="file ricomposto")
    r.add_argument("--nome", default=None,
                   help="cattura da ricomporre; necessaria con più catture")
    v = sotto.add_parser(Operazione.VERIFICA.value, help="controlla parti e impronte")
    v.add_argument("archivio", type=Path, help="cartella d'archivio")
    v.add_argument("--ricomponendo", action="store_true",
                   help="ricompone anche per verificare l'impronta dell'originale")
    p = sotto.add_parser(Operazione.PILOTA.value, help="confronto dei livelli di compressione su una cattura")
    p.add_argument("sorgente", type=Path, help="cattura pcap da comprimere")
    p.add_argument("--livelli", default="3,9,19",
                   help="livelli di zstd da provare, separati da virgola")
    p.add_argument("--cartella", type=Path, default=Path("data/pilota-catture"),
                   help="cartella di lavoro del confronto")
    args = ap.parse_args(argv)
    match args.azione:
        case Operazione.COMPRIMI:
            m = comprimi(args.esecuzione, args.destinazione, args.livello, cancella=args.cancella)
            for voce in m["catture"]:
                print(f"{voce['nome']}: {voce['byte']} -> {voce['byte_compressi']} byte "
                      f"(x{voce['rapporto']}), {len(voce['parti'])} parti, {voce['secondi']} s")
        case Operazione.RICOMPONI:
            print(ricomponi(args.archivio, args.uscita, args.nome))
        case Operazione.VERIFICA:
            problemi = verifica(args.archivio, ricomponendo=args.ricomponendo)
            print("\n".join(problemi) or "integro")
            sys.exit(1 if problemi else 0)
        case _:
            livelli = [int(x) for x in args.livelli.split(",")]
            print(json.dumps(pilota(args.sorgente, livelli, args.cartella), indent=2))


if __name__ == "__main__":
    main()
