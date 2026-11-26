from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from ids.parametri import GENERAZIONE
from model.config import ScenarioSpec
from orchestrator.run import Experiment, applica_varianti

SPAZIO_INONDAZIONE_MB = 8000
SPAZIO_NORMALE_MB = 2000

PERIODO_S = 5.0


@dataclass
class Lavoro:
    posizione: int
    yaml: str
    opzioni: list[str]
    id_scenario: str
    chiave: str
    impara: bool
    esclusivo: bool
    spazio_mb: int
    run_id: str = ""
    stato: str = "in attesa"
    core: str | None = None
    processo: subprocess.Popen | None = field(default=None, repr=False)
    inizio: float = 0.0
    fine: float = 0.0
    esito: int | None = None
    problemi: list[str] = field(default_factory=list)


def leggi_piano(testo: str) -> list[tuple[str, list[str]]]:
    righe = []
    for riga in testo.splitlines():
        riga = riga.split("#", 1)[0].strip()
        if not riga:
            continue
        parti = shlex.split(riga)
        righe.append((parti[0], parti[1:]))
    return righe


def _opzione(opzioni: list[str], nome: str) -> str | None:
    for i, o in enumerate(opzioni):
        if o == nome and i + 1 < len(opzioni):
            return opzioni[i + 1]
        if o.startswith(f"{nome}="):
            return o.split("=", 1)[1]
    return None


def _tutte(opzioni: list[str], nome: str) -> list[str]:
    valori = []
    for i, o in enumerate(opzioni):
        if o == nome and i + 1 < len(opzioni):
            valori.append(opzioni[i + 1])
        elif o.startswith(f"{nome}="):
            valori.append(o.split("=", 1)[1])
    return valori


def _trasporto(opzioni: list[str]) -> str | None:
    return _opzione(opzioni, "--trasporto")


def scenario_con_opzioni(yaml: str, opzioni: list[str]) -> ScenarioSpec:
    perdita = _opzione(opzioni, "--perdita")
    return applica_varianti(ScenarioSpec.da_file(yaml), _trasporto(opzioni),
                            float(perdita) if perdita is not None else None,
                            _tutte(opzioni, "--variante"))


def prepara_lavori(righe: list[tuple[str, list[str]]], dati: str) -> list[Lavoro]:
    lavori = []
    imparate: set[str] = set()
    for k, (yaml, opzioni) in enumerate(righe):
        s = scenario_con_opzioni(yaml, opzioni)
        e = Experiment(s, dati, run_id=f"pianificazione-{k}",
                       rifai_profilo="--rifai-profilo" in opzioni)
        decisione = e.decisione_profilo()
        impara = bool(decisione["impara"])
        sempre = "--rifai-profilo" in opzioni or bool(s.visibilita)
        if impara and not sempre and decisione["chiave"] in imparate:
            impara = False
        if impara:
            imparate.add(decisione["chiave"])
        esclusivo = s.ramo == "inondazione"
        lavori.append(Lavoro(
            posizione=k, yaml=yaml, opzioni=list(opzioni), id_scenario=s.id,
            chiave=decisione["chiave"], impara=impara, esclusivo=esclusivo,
            spazio_mb=SPAZIO_INONDAZIONE_MB if esclusivo else SPAZIO_NORMALE_MB))
    return lavori


def nuovo_run_id(id_scenario: str) -> str:
    return f"{id_scenario}-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"


def puo_partire(lavoro: Lavoro, lavori: list[Lavoro], slot: int,
                libero_mb: int | None) -> tuple[bool, str]:
    in_corso = [l for l in lavori if l.stato == "in corso"]
    precedenti = [l for l in lavori if l.posizione < lavoro.posizione]
    if len(in_corso) >= slot:
        return False, "slot occupati"
    if any(l.esclusivo for l in in_corso):
        return False, "esecuzione esclusiva in corso"
    if lavoro.esclusivo and in_corso:
        return False, "esecuzione esclusiva: attesa della fine delle altre"
    if any(l.esclusivo and l.stato == "in attesa" for l in precedenti):
        return False, "attesa dell'esecuzione esclusiva precedente"
    for l in precedenti:
        if l.chiave != lavoro.chiave or l.stato in ("finito",):
            continue
        if l.impara or lavoro.impara:
            return False, f"attesa di {l.id_scenario}: stessa chiave di profilo"
    if libero_mb is not None:
        impegnato = sum(l.spazio_mb for l in in_corso)
        if libero_mb - impegnato < lavoro.spazio_mb:
            return False, (f"spazio insufficiente: {libero_mb - impegnato} MB disponibili, "
                           f"{lavoro.spazio_mb} MB richiesti")
    return True, ""


def core_per_slot(slot: int, processori: int | None = None) -> list[str]:
    processori = processori or os.cpu_count() or 1
    per = max(1, processori // max(1, slot))
    if slot <= 1 or per * slot > processori:
        return []
    return [f"{k * per}-{k * per + per - 1}" if per > 1 else str(k * per)
            for k in range(slot)]


def problemi_dell_esecuzione(radice: Path, esito: int) -> list[str]:
    problemi = []
    if esito != 0:
        problemi.append(f"codice d'uscita {esito}")
    f = radice / "config" / "riepilogo.json"
    if not f.exists():
        return problemi + ["riepilogo assente: esecuzione incompleta"]
    r = json.loads(f.read_text(encoding="utf-8"))
    if r.get("rtt_conforme") is not True:
        problemi.append("canale non conforme")
    if r.get("raccolta_completa") is False:
        problemi.append("raccolta incompleta")
    if r.get("visibilita_caricata") is False:
        problemi.append("calendario dei passaggi non caricato da tutti i nodi")
    if not (radice / "local" / "riepilogo_ids.json").exists():
        problemi.append("riepilogo dell'IDS assente: IDS non eseguito")
    profilo = r.get("profilo_depositato")
    if profilo:
        try:
            g = json.loads(Path(profilo).read_text(encoding="utf-8")).get("globale", {})
            if not (g.get("sessioni_aperte") or {}).get("massimo"):
                problemi.append("profilo appreso senza sessioni_aperte")
        except (OSError, ValueError):
            problemi.append("profilo depositato illeggibile")
    return problemi


def problemi_delle_metriche(metriche: dict) -> list[str]:
    problemi = []
    for e in metriche.get("esecuzioni", []):
        if e.get("generazione") != GENERAZIONE:
            problemi.append(f"generazione {e.get('generazione')}, attesa {GENERAZIONE}")
    return problemi


class GestoreSerie:
    def __init__(self, lavori: list[Lavoro], args: argparse.Namespace) -> None:
        self.lavori = lavori
        self.args = args
        self.registro = Path(args.registro)
        self.registro.mkdir(parents=True, exist_ok=True)
        self.core = core_per_slot(args.parallelo) if args.isola_core else []
        self.fermo = False
        self.python = sys.executable
        self.catture = None
        if args.catture:
            from analysis.catture import CodaCatture
            serie = Path(args.esporta).name if args.esporta else self.registro.name
            self.catture = CodaCatture(self.registro / "catture-in-coda", Path(args.catture),
                                       serie, args.dopo_catture, self.scrivi,
                                       livello=args.livello_catture)

    def scrivi(self, testo: str) -> None:
        print(f"=== {testo}", flush=True)

    def libero_mb(self) -> int:
        st = os.statvfs(self.args.dati)
        return int(st.f_bavail * st.f_frsize / (1024 * 1024))

    def _core_libero(self) -> str | None:
        occupati = {l.core for l in self.lavori if l.stato == "in corso"}
        for c in self.core:
            if c not in occupati:
                return c
        return None

    def avvia(self, l: Lavoro) -> None:
        l.run_id = nuovo_run_id(l.id_scenario)
        l.core = None if l.esclusivo else self._core_libero()
        comando = [self.python, "-m", "orchestrator.run", l.yaml, *l.opzioni,
                   "--dati", self.args.dati, "--run-id", l.run_id]
        if l.core:
            comando += ["--core", l.core]
        log = open(self.registro / f"{l.run_id}.log", "w", encoding="utf-8")
        l.processo = subprocess.Popen(comando, stdout=log, stderr=subprocess.STDOUT)
        l.stato, l.inizio = "in corso", time.time()
        self.scrivi(f"{l.id_scenario} avvio {l.run_id} {' '.join(l.opzioni)}"
                    + (f" core {l.core}" if l.core else ""))

    def concludi(self, l: Lavoro) -> None:
        l.esito, l.fine = l.processo.returncode, time.time()
        radice = Path(self.args.dati) / "runs" / l.run_id
        problemi = problemi_dell_esecuzione(radice, l.esito)
        riep = radice / "config" / "riepilogo.json"
        if riep.exists():
            h = json.loads(riep.read_text(encoding="utf-8")).get("laboratorio_hash")
            if h:
                accesi = subprocess.run(["docker", "ps", "-q", "--filter", f"label=lab_hash={h}"],
                                        capture_output=True, text=True).stdout.split()
                if accesi:
                    problemi.append(f"{len(accesi)} container del laboratorio ancora accesi")
        if radice.exists():
            m = subprocess.run([self.python, "-m", "analysis.metrics", str(radice)],
                               capture_output=True, text=True)
            if m.returncode != 0 or "Traceback" in m.stderr:
                problemi.append("analysis.metrics non riuscito: " + m.stderr.strip()[-300:])
            else:
                (radice / "metriche.json").write_text(m.stdout, encoding="utf-8")
                problemi += problemi_delle_metriche(json.loads(m.stdout))
            o = subprocess.run([self.python, "-m", "analysis.omniscient", str(radice)],
                               capture_output=True, text=True)
            if o.returncode == 0:
                (radice / "onnisciente.json").write_text(o.stdout, encoding="utf-8")
        l.problemi = problemi
        l.stato = "fermo" if problemi else "finito"
        self.scrivi(f"{l.id_scenario} {l.run_id} fine esito {l.esito}"
                    + (" - FERMO: " + "; ".join(problemi) if problemi else ""))
        with open(self.registro / "elenco.tsv", "a", encoding="utf-8") as f:
            f.write("\t".join([l.id_scenario, l.run_id, _ora(l.inizio), _ora(l.fine),
                               str(l.esito), " ".join(l.opzioni), l.core or "",
                               "; ".join(problemi)]) + "\n")
        if problemi:
            self.fermo = True
            return
        esportata = Path(self.args.esporta) / l.run_id if self.args.esporta else radice
        if self.args.esporta:
            esporta(radice, esportata)
        if self.args.dopo:
            with open(self.registro / ".lucchetto", "w") as lucchetto:
                fcntl.flock(lucchetto, fcntl.LOCK_EX)
                comando = self.args.dopo.format(id=l.run_id, cartella=radice,
                                                esportata=esportata,
                                                scenario=l.id_scenario)
                esito = subprocess.run(comando, shell=True).returncode
            if esito != 0:
                self.scrivi(f"comando successivo a {l.run_id} terminato con codice {esito}")
        if self.catture is not None and self.catture.accoda(radice, l.run_id):
            self.scrivi(f"{l.run_id} cattura in coda di compressione")
        if self.args.esporta and not re.search(self.args.tieni, l.id_scenario):
            shutil.rmtree(radice, ignore_errors=True)

    def alla_fine(self) -> None:
        if not self.args.esporta or not self.args.grafici:
            return
        cartella = Path(self.args.esporta)
        if not cartella.exists():
            return
        g = subprocess.run([self.python, "-m", "analysis.grafici", "serie", str(cartella)],
                           capture_output=True, text=True)
        self.scrivi("grafici della serie " + ("scritti in " + str(cartella / "grafici")
                    if g.returncode == 0 else "non riusciti: " + g.stderr.strip()[-300:]))
        if self.args.dopo_serie:
            with open(self.registro / ".lucchetto", "w") as lucchetto:
                fcntl.flock(lucchetto, fcntl.LOCK_EX)
                esito = subprocess.run(self.args.dopo_serie.format(
                    cartella=cartella, esportata=cartella),
                                       shell=True).returncode
            if esito != 0:
                self.scrivi(f"comando di fine serie terminato con codice {esito}")

    def esegui(self) -> int:
        if self.args.verifica:
            primo = self.lavori[0]
            esito = subprocess.run([self.python, "-m", "orchestrator.run", "scenarios/D1.yaml",
                                    "--verifica-apparato", "--dati", self.args.dati,
                                    *(["--trasporto", _trasporto(primo.opzioni)]
                                      if _trasporto(primo.opzioni) else [])],
                                   stdout=open(self.registro / "verifica-apparato.txt", "w"),
                                   stderr=subprocess.STDOUT).returncode
            self.scrivi(f"verifica dell'apparato: codice {esito}")
            if esito != 0:
                return 1
        while True:
            for l in self.lavori:
                if l.stato == "in corso" and l.processo.poll() is not None:
                    self.concludi(l)
            in_corso = [l for l in self.lavori if l.stato == "in corso"]
            in_attesa = [l for l in self.lavori if l.stato == "in attesa"]
            if self.fermo or not in_attesa:
                if not in_corso:
                    break
            else:
                perche = ""
                for l in in_attesa:
                    ok, motivo = puo_partire(l, self.lavori, self.args.parallelo,
                                             self.libero_mb())
                    if ok:
                        self.avvia(l)
                    elif not perche:
                        perche = f"{l.id_scenario}: {motivo}"
                if not any(l.stato == "in corso" for l in self.lavori):
                    self.scrivi(f"serie interrotta: {perche}")
                    self.fermo = True
                    break
            time.sleep(PERIODO_S)
        fermi = [l for l in self.lavori if l.stato == "fermo"]
        self.alla_fine()
        if self.catture is not None:
            self.scrivi("attesa dello svuotamento della coda delle catture")
            self.catture.aspetta()
        self.scrivi("SERIE " + ("FERMATA" if fermi or self.fermo else "COMPLETA")
                    + f" {time.strftime('%Y-%m-%dT%H:%M:%S')}")
        return 2 if fermi or self.fermo else 0


def _ora(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t)) if t else ""


def esporta(radice: Path, destinazione: Path) -> None:
    destinazione.mkdir(parents=True, exist_ok=True)
    for relativo in ("config/run.json", "config/riepilogo.json", "config/attacco.json",
                     "config/orario.json", "config/visibilita.json",
                     "config/profilo_riusato.json",
                     "truth/etichette.jsonl", "local/allarmi.jsonl",
                     "local/riepilogo_ids.json", "analysis/servizio.json",
                     "metriche.json", "onnisciente.json"):
        f = radice / relativo
        if f.exists():
            shutil.copy2(f, destinazione / f.name)
    indice = radice / "omniscient" / "indice.json"
    if indice.exists():
        shutil.copy2(indice, destinazione / "indice-osservatore.json")
    for profilo in (radice / "local" / "profilo").rglob("profilo.json"):
        shutil.copy2(profilo, destinazione / "profilo.json")
    (destinazione / "local").mkdir(exist_ok=True)
    for vista in (radice / "local").glob("*.jsonl.gz"):
        if vista.stat().st_size <= 50_000_000:
            shutil.copy2(vista, destinazione / "local" / vista.name)
        else:
            with open(destinazione / "viste-non-pubblicate.txt", "a", encoding="utf-8") as f:
                f.write(f"{vista.name} {vista.stat().st_size} byte, non pubblicata\n")


def argomenti(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Esecuzione di una serie da un piano")
    ap.add_argument("piano", help="piano, una voce per esecuzione con scenario e opzioni")
    ap.add_argument("--parallelo", type=int, default=1,
                    help="esecuzioni contemporanee al più")
    ap.add_argument("--dati", default="data", help="cartella dei dati delle esecuzioni")
    ap.add_argument("--registro", required=True, help="cartella per i registri della serie")
    ap.add_argument("--esporta", default=None,
                    help="cartella dei file compatti delle esecuzioni")
    ap.add_argument("--dopo", default=None,
                    help="comando dopo ogni esecuzione valida, con {id}, {scenario}, "
                         "{cartella} e {esportata}")
    ap.add_argument("--dopo-serie", default=None,
                    help="comando a fine serie, con {cartella} e {esportata}")
    ap.add_argument("--catture", default=None,
                    help="copia locale del repository delle catture")
    ap.add_argument("--dopo-catture", default=None,
                    help="comando dopo ogni cattura compressa; sostituisce {id} e {cartella}")
    ap.add_argument("--livello-catture", type=int, default=19,
                    help="livello di compressione zstd")
    ap.add_argument("--grafici", dest="grafici", action="store_true",
                    help="produce i grafici a fine serie")
    ap.add_argument("--senza-grafici", dest="grafici", action="store_false",
                    help="nessun grafico a fine serie (predefinito)")
    ap.set_defaults(grafici=False)
    ap.add_argument("--tieni", default=r"^$",
                    help="regex degli scenari di cui tenere la cartella grezza")
    ap.add_argument("--senza-verifica", dest="verifica", action="store_false",
                    help="salta la verifica iniziale dell'apparato sperimentale")
    ap.add_argument("--senza-isolare-core", dest="isola_core", action="store_false",
                    help="nessun processore dedicato per slot")
    args = ap.parse_args(argv)
    for nome, valore in (("--dopo", args.dopo), ("--dopo-serie", args.dopo_serie)):
        if valore and "{esportata}" in valore and not args.esporta:
            ap.error(f"{nome} usa {{esportata}} senza --esporta")
    return args


def main() -> None:
    args = argomenti()
    righe = leggi_piano(Path(args.piano).read_text(encoding="utf-8"))
    lavori = prepara_lavori(righe, args.dati)
    raise SystemExit(GestoreSerie(lavori, args).esegui())


if __name__ == "__main__":
    main()
