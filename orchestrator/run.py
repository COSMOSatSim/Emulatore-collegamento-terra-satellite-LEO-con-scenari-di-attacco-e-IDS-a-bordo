from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import statistics
import subprocess
import tarfile
import time
import uuid
from pathlib import Path
from typing import Any

from ids.parametri import GENERAZIONE
from ids.profile import ArchivioProfili, NormalityProfile, ProfiloOccupato
from model.config import Ruolo, RunConfig, ScenarioSpec, TransportProfile
from common.transport import carica_algoritmo
from common.visibilita import risolvi as risolvi_visibilita
from model.events import NODO_VISIBILITA, leggi_tutto
from orchestrator.lab import (IMMAGINE_BASE, ORARIO, ORDINE_ATTACCO, VISIBILITA,
                              nodi_dello_scenario, scrivi_laboratorio, seme_di)
from orchestrator.phases import GroundTruthRecorder, PhaseScheduler


class LabController:
    def __init__(self, cartella: str | Path) -> None:
        self.cartella = Path(cartella)
        self._api = None
        try:
            from Kathara.manager.Kathara import Kathara
            self._api = Kathara.get_instance()
        except Exception:
            self._api = None

    @property
    def modalita(self) -> str:
        if self._api is not None:
            return "api-python"
        return "comando" if shutil.which("kathara") else "assente"

    def _comando(self, *args: str) -> int:
        if shutil.which("kathara") is None:
            raise RuntimeError("Kathará non installato")
        return subprocess.run(["kathara", *args], cwd=str(self.cartella)).returncode

    def avvia(self) -> None:
        self._comando("lstart", "--noterminals")

    def arresta(self) -> None:
        self._comando("lclean")

    @property
    def hash(self) -> str:
        return hash_del_laboratorio(self.cartella)

    def container(self) -> list[str]:
        uscita = subprocess.run(
            ["docker", "ps", "-q", "--filter", f"label=lab_hash={self.hash}"],
            capture_output=True, text=True, timeout=20).stdout.split()
        return uscita

    def fissa_core(self, core: str) -> int:
        fatti = 0
        for ident in self.container():
            esito = subprocess.run(["docker", "update", "--cpuset-cpus", core, ident],
                                   capture_output=True, text=True, timeout=30)
            if esito.returncode != 0:
                raise RuntimeError(f"core {core} non assegnati a {ident}: "
                                   + (esito.stderr or "").strip())
            fatti += 1
        return fatti

    def concludi(self, nodi: list[str], attesa: float = 6.0) -> None:
        for nodo in nodi:
            try:
                self.esegui_su(nodo, "pkill -TERM -f 'python3 -m' || true")
            except Exception:
                continue
        time.sleep(attesa)

    def raccogli(self, nodi: list[str], radice: Path) -> list[str]:
        if self._api is None:
            raise RuntimeError("raccolta dei dati: interfaccia Python di Kathará assente")
        from Kathara.parser.netkit.LabParser import LabParser
        lab = LabParser.parse(str(self.cartella.resolve()))
        copiati: list[str] = []
        saltati: list[str] = []
        for nodo in nodi:
            contenitore = self._api.get_machine_api_object(nodo, lab=lab)
            for sotto in ("local", "omniscient"):
                try:
                    flusso, _ = contenitore.get_archive(f"/dati/{sotto}")
                except Exception:
                    continue
                with tarfile.open(fileobj=io.BytesIO(b"".join(flusso))) as archivio:
                    membri = sorted(archivio.getmembers(),
                                    key=lambda m: m.size if m.isfile() else 0)
                    for membro in membri:
                        parti = Path(membro.name).parts[1:]
                        if not parti:
                            continue
                        membro.name = str(Path(*parti))
                        try:
                            archivio.extract(membro, radice / sotto, filter="data")
                        except OSError as errore:
                            saltati.append(f"{sotto}/{membro.name}: {errore}")
                            continue
                        if membro.isfile():
                            copiati.append(f"{sotto}/{membro.name}")
        self.saltati_in_raccolta = saltati
        copiati += self._comprimi_viste(nodi, radice)
        return copiati

    @staticmethod
    def _comprimi_viste(nodi: list[str],
                        radice: Path) -> list[str]:
        import gzip
        import shutil

        fatti: list[str] = []
        for nodo in nodi:
            vista = radice / "local" / f"{nodo}.jsonl"
            if not vista.is_file():
                continue
            compressa = vista.with_suffix(".jsonl.gz")
            try:
                with vista.open("rb") as sorgente, \
                        gzip.open(compressa, "wb", compresslevel=6) as uscita:
                    shutil.copyfileobj(sorgente, uscita)
                vista.unlink()
            except OSError:
                continue
            fatti.append(f"local/{compressa.name}")
        return fatti

    @staticmethod
    def _riga(*argomenti: str) -> str:
        return shlex.join(argomenti)

    def esegui_su(self, dispositivo: str, comando: str) -> None:
        self._comando("exec", dispositivo, self._riga("sh", "-c", comando))

    def _uscita_di(self, dispositivo: str, comando: str,
                   attesa: float = 30.0) -> str:
        try:
            esito = subprocess.run(
                ["kathara", "exec", dispositivo, self._riga("sh", "-c", comando)],
                cwd=str(self.cartella), capture_output=True, text=True, timeout=attesa)
            return (esito.stdout or "") + (esito.stderr or "")
        except (OSError, subprocess.SubprocessError):
            return ""

    def deposita_su(self, dispositivo: str, percorso: str,
                    contenuto: str) -> bool:
        cartella = str(Path(percorso).parent).replace("\\", "/")
        comando = (f"mkdir -p {shlex.quote(cartella)} && "
                   f"printf %s {shlex.quote(contenuto)} > {shlex.quote(percorso)}")
        try:
            if self._comando("exec", dispositivo,
                             self._riga("sh", "-c", comando)) != 0:
                return False
        except RuntimeError:
            return False
        letto = self._uscita_di(dispositivo, f"cat {shlex.quote(percorso)}")
        return contenuto.strip() in letto

    def verifica_trasporto(self, dispositivo: str,
                           atteso: str) -> tuple[bool, str]:
        uscita = self._uscita_di(
            dispositivo, "sysctl -n net.ipv4.tcp_congestion_control").strip()
        effettivo = uscita.splitlines()[-1].strip() if uscita else ""
        if not effettivo:
            return True, "(non misurato)"
        return effettivo == atteso, effettivo

    PROIBITI = ("/dati/omniscient", "/dati/truth", "/shared/attacco.json",
                "/dati/local/attacker.jsonl", "/dati/local/ground1.jsonl",
                "/dati/local/observer.jsonl")

    def verifica_isolamento(self, dispositivo: str = "satellite",
                            proibiti: tuple[str, ...] | None = None
                            ) -> list[str]:
        visibili: list[str] = []
        for percorso in (proibiti or self.PROIBITI):
            q = shlex.quote(percorso)
            uscita = self._uscita_di(
                dispositivo,
                f'if [ -d {q} ]; then [ -n "$(ls -A {q} 2>/dev/null)" ] '
                f"&& echo VISIBILE || echo NO; "
                f"elif [ -e {q} ]; then echo VISIBILE; else echo NO; fi")
            if "VISIBILE" in uscita:
                visibili.append(percorso)
        return visibili

    @staticmethod
    def _tempi_ping(uscita: str) -> list[float]:
        tempi = []
        for riga in uscita.splitlines():
            if "time=" in riga:
                try:
                    tempi.append(float(riga.split("time=")[1].split()[0]))
                except (IndexError, ValueError):
                    continue
        return tempi

    def verifica_rtt(self, dispositivo: str, destinazione: str,
                     atteso_ms: float, tolleranza: float = 0.35,
                     campioni: int = 20, assestamento_s: float = 10.0,
                     tolleranza_ms: float | None = None,
                     atteso_massimo_ms: float | None = None) -> bool:
        time.sleep(assestamento_s)
        try:
            subprocess.run(
                ["kathara", "exec", dispositivo,
                 self._riga("ping", "-c", "1", "-q", destinazione)],
                cwd=str(self.cartella), capture_output=True, text=True, timeout=30)
            out = subprocess.run(
                ["kathara", "exec", dispositivo,
                 self._riga("ping", "-c", str(campioni), "-i", "0.2", destinazione)],
                cwd=str(self.cartella), capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            return False
        tempi = self._tempi_ping(out.stdout)
        if len(tempi) < campioni // 2:
            return False
        margine = tolleranza_ms if tolleranza_ms is not None else atteso_ms * tolleranza
        massimo = atteso_ms if atteso_massimo_ms is None else atteso_massimo_ms
        return rtt_accettabile(statistics.median(tempi), atteso_ms, massimo, margine)


def rtt_accettabile(mediana_ms: float, atteso_ms: float, massimo_ms: float,
                    margine_ms: float) -> bool:
    return atteso_ms - margine_ms <= mediana_ms <= massimo_ms + margine_ms


def tempi_attesi_per_nodo(s: ScenarioSpec) -> dict[str, float]:
    if not s.canali_per_nodo:
        return {}
    nodi = [n.nome for n in nodi_dello_scenario(s) if n.ruolo in (Ruolo.GROUND, Ruolo.ATTACKER)]
    return {n: s.canale.ritardo_ms + s.canale_di(n).ritardo_ms for n in nodi}


def tempi_massimi_per_nodo(s: ScenarioSpec) -> dict[str, float]:
    if not s.canali_per_nodo:
        return {}
    nodi = [n.nome for n in nodi_dello_scenario(s) if n.ruolo in (Ruolo.GROUND, Ruolo.ATTACKER)]
    return {n: s.canale.ritardo_massimo_ms + s.ritardo_massimo_di(n) for n in nodi}


CARTELLE_DEL_CODICE = ("model", "common", "app", "sensor", "ids", "observer",
                       "orchestrator", "analysis", "images", "requirements.txt")

ETICHETTA_CODICE = "it.tirocinio.codice"


def codice_del_repository(radice: str | Path | None = None) -> dict:
    radice = Path(radice) if radice else Path(__file__).resolve().parent.parent
    try:
        commit = subprocess.run(
            ["git", "-C", str(radice), "log", "-1", "--format=%H", "--",
             *CARTELLE_DEL_CODICE],
            capture_output=True, text=True, timeout=10).stdout.strip() or None
        modifiche = subprocess.run(
            ["git", "-C", str(radice), "status", "--porcelain",
             "--untracked-files=no", "--", *CARTELLE_DEL_CODICE],
            capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return {"commit": None, "modifiche_locali": None}
    return {"commit": commit, "modifiche_locali": bool(modifiche) if commit else None}


def etichetta_dell_immagine(nome: str = IMMAGINE_BASE) -> dict:
    formato = "{{.Id}} {{index .Config.Labels \"" + ETICHETTA_CODICE + "\"}}"
    try:
        uscita = subprocess.run(["docker", "image", "inspect", "--format", formato, nome],
                                capture_output=True, text=True, timeout=20).stdout.split()
    except (OSError, subprocess.SubprocessError):
        return {"nome": nome, "id": None, "codice": None}
    return {"nome": nome, "id": uscita[0] if uscita else None,
            "codice": uscita[1] if len(uscita) > 1 and uscita[1] != "<no" else None}


def problema_di_provenienza(codice: dict, immagine: dict) -> str | None:
    nel_codice, nell_immagine = codice.get("commit"), immagine.get("codice")
    if not nel_codice or not nell_immagine or nell_immagine == "sconosciuto":
        return None
    if nell_immagine != nel_codice:
        return (f"immagine {immagine.get('nome')} del codice {nell_immagine[:7]}, "
                f"cartella al codice {nel_codice[:7]}: immagine da ricostruire")
    if codice.get("modifiche_locali"):
        return ("modifiche locali non registrate: provenienza dell'immagine non "
                "verificabile")
    return None


def hash_del_laboratorio(cartella: str | Path) -> str:
    percorso = re.sub(r"[^\x00-\x7F]+", "", os.path.realpath(str(cartella)))
    impronta = hashlib.md5(percorso.encode("utf-8", errors="ignore")).digest()
    return (base64.urlsafe_b64encode(impronta)[:-2].decode("utf-8")
            .replace("-", "").replace("_", ""))


def leggi_cpu_stat(testo: str) -> dict[str, int]:
    valori: dict[str, int] = {}
    for riga in (testo or "").splitlines():
        parti = riga.split()
        if len(parti) == 2:
            try:
                valori[parti[0]] = int(parti[1])
            except ValueError:
                continue
    return valori


def laboratori_kathara_accesi() -> int | None:
    try:
        uscita = subprocess.run(
            ["docker", "ps", "--filter", "label=app=kathara",
             "--format", '{{.Label "lab_hash"}}'],
            capture_output=True, text=True, timeout=20).stdout.split()
    except (OSError, subprocess.SubprocessError):
        return None
    return len(set(uscita))


def generazione_del_profilo(percorso: str | Path) -> str | None:
    try:
        return json.loads(Path(percorso).read_text(encoding="utf-8")).get("generazione")
    except (OSError, ValueError, AttributeError):
        return None


def nodi_senza_calendario(radice: str | Path, nodi: list[str]) -> list[str]:
    mancanti = []
    for nodo in nodi:
        eventi = leggi_tutto(Path(radice) / "local" / f"{nodo}.jsonl")
        if not any(ev.tipo == NODO_VISIBILITA and ev.dati.get("finestre", 0) > 0
                   for ev in eventi):
            mancanti.append(nodo)
    return mancanti


class Experiment:
    def __init__(self, scenario: ScenarioSpec, radice_dati: str | Path = "data",
                 run_id: str | None = None, archivio: ArchivioProfili | None = None,
                 rifai_profilo: bool = False, core: str | None = None) -> None:
        self.scenario = scenario
        self.run_id = run_id or f"{scenario.id}-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
        self.radice = Path(radice_dati) / "runs" / self.run_id
        self.archivio = archivio or ArchivioProfili(Path(radice_dati) / "profiles")
        self.rifai_profilo = rifai_profilo
        self.profilo_riusato: str | None = None
        self.motivo_profilo: str | None = None
        self.core = core
        self.banco: dict = {"core": core, "campioni": []}
        self.config = RunConfig(
            run_id=self.run_id, scenario_id=scenario.id, topologia=scenario.topologia,
            canale=scenario.canale, trasporto=scenario.trasporto,
            punto_di_cattura=scenario.punto_di_cattura,
            immagini={"base": IMMAGINE_BASE},
            visibilita=scenario.visibilita,
            carico=scenario.carico_nominale,
            carico_per_stazione=scenario.carico_per_stazione,
            canali_per_nodo=scenario.canali_per_nodo)
        if scenario.seme is None:
            import random
            scenario.seme = random.SystemRandom().randrange(1, 2 ** 31)

    def decisione_profilo(self) -> dict:
        chiave = self.config.chiave_profilo()
        if self.rifai_profilo:
            return {"chiave": chiave, "impara": True, "motivo": "--rifai-profilo"}
        if not self.archivio.esiste(chiave):
            return {"chiave": chiave, "impara": True, "motivo": "nessun profilo in archivio"}
        appreso_con = generazione_del_profilo(self.archivio.percorso(chiave))
        if appreso_con != GENERAZIONE:
            return {"chiave": chiave, "impara": True, "motivo": (
                "profilo in archivio non riusato: generazione "
                + (appreso_con or "non dichiarata")
                + f", codice a {GENERAZIONE}")}
        if self.scenario.visibilita:
            return {"chiave": chiave, "impara": True, "motivo": (
                "profilo in archivio non riusato: scenario con finestre di "
                "visibilità")}
        return {"chiave": chiave, "impara": False, "motivo": None}

    def _decidi_profilo(self) -> tuple[str | None, dict[str, int]]:
        fasi = dict(self.scenario.fasi)
        chiave = self.config.chiave_profilo()
        decisione = self.decisione_profilo()
        if decisione["impara"]:
            if decisione["motivo"] and decisione["motivo"].startswith("profilo in archivio"):
                self.motivo_profilo = decisione["motivo"]
            return None, fasi
        sorgente = self.archivio.percorso(chiave)
        destinazione = self.radice / "config" / "profilo_riusato.json"
        destinazione.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(sorgente, destinazione)
        fasi["nominale"] = 0
        return str(sorgente), fasi

    def _deposita_profilo(self) -> str | None:
        appreso = self.radice / "local" / "profilo" / self.config.chiave_profilo() \
            / "profilo.json"
        if not appreso.exists():
            return None
        try:
            profilo = NormalityProfile.carica(appreso)
            profilo.origine.update({"esecuzione": self.radice.name,
                                    "codice": codice_del_repository(),
                                    "finestre": profilo.finestre})
            depositato = self.archivio.deposita(profilo)
            shutil.copyfile(depositato, appreso)
            return str(depositato)
        except (ValueError, OSError):
            return None

    def _impronta_profilo(self) -> tuple[str | None, dict | None]:
        copia = self.radice / "config" / "profilo_riusato.json"
        if not copia.exists():
            return None, None
        import hashlib
        impronta = hashlib.sha256(copia.read_bytes()).hexdigest()
        try:
            origine = json.loads(copia.read_text(encoding="utf-8")).get("origine")
        except (ValueError, OSError):
            origine = None
        return impronta, origine

    def prepara(self) -> Path:
        problemi = self.scenario.valida()
        if problemi:
            raise ValueError("scenario non valido: " + "; ".join(problemi))
        for sotto in ("config", "local", "omniscient", "truth", "analysis"):
            (self.radice / sotto).mkdir(parents=True, exist_ok=True)
        self.profilo_riusato, self.fasi_effettive = self._decidi_profilo()
        conf = self.config.come_dict()
        conf["profilo_riusato"] = self.profilo_riusato
        conf["fase_nominale_saltata"] = self.profilo_riusato is not None
        conf["motivo_profilo"] = self.motivo_profilo
        conf["profilo_impronta"], conf["profilo_origine"] = self._impronta_profilo()
        conf["seme"] = self.scenario.seme
        conf["semi"] = {n.nome: seme_di(self.scenario.seme, n.nome)
                        for n in nodi_dello_scenario(self.scenario)
                        if n.ruolo in (Ruolo.GROUND, Ruolo.ATTACKER)}
        conf["codice"] = codice_del_repository()
        (self.radice / "config" / "run.json").write_text(
            json.dumps(conf, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        cartella_lab = scrivi_laboratorio(self.scenario, self.radice / "lab",
                                          self.profilo_riusato,
                                          self.config.chiave_profilo())
        return cartella_lab

    def _misura_servizio(self) -> None:
        from analysis.servizio import valuta_cartella
        try:
            misura = valuta_cartella(self.radice)
            (self.radice / "analysis").mkdir(parents=True, exist_ok=True)
            (self.radice / "analysis" / "servizio.json").write_text(
                json.dumps(misura, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    def _nodo_con_ids(self) -> str:
        return "satellite"

    def _campiona_banco(self, fase: str, finto: bool) -> None:
        try:
            carico = round(os.getloadavg()[0], 2)
        except OSError:
            carico = None
        self.banco["campioni"].append({
            "fase": fase, "t": round(time.time(), 3), "carico_1min": carico,
            "laboratori_accesi": None if finto else laboratori_kathara_accesi()})

    def _aggiungi_a_run_json(self, campo: str, valore: Any) -> None:
        f = self.radice / "config" / "run.json"
        conf = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
        conf[campo] = valore
        f.write_text(json.dumps(conf, indent=2, ensure_ascii=False, default=str),
                     encoding="utf-8")

    def _registra(self, nome: str, contenuto: dict) -> None:
        try:
            f = self.radice / "config" / nome
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(json.dumps(contenuto, indent=2, ensure_ascii=False),
                         encoding="utf-8")
        except OSError:
            pass

    def _deposita_orario(self, controller: "LabController", inizio: float,
                         finto: bool) -> str:
        dati = {"inizio": inizio}
        self._registra("orario.json", dati)
        if finto:
            return "orario non depositato: esecuzione simulata"
        nodo = self._nodo_con_ids()
        if controller.deposita_su(nodo, ORARIO, json.dumps(dati)):
            return f"orario depositato su {nodo}"
        return "orario non depositato: fasi contate dall'avvio dell'IDS"

    def _destinatari_visibilita(self) -> list[str]:
        return [n.nome for n in nodi_dello_scenario(self.scenario)
                if n.ruolo in (Ruolo.SATELLITE, Ruolo.GROUND)]

    def _scrivi_visibilita_nel_laboratorio(self, cartella_lab: Path,
                                           inizio: float) -> str:
        if not self.scenario.visibilita:
            return ""
        dati = risolvi_visibilita(self.scenario.visibilita, inizio)
        self._registra("visibilita.json", dati)
        destinatari = self._destinatari_visibilita()
        testo = json.dumps(dati)
        for nodo in destinatari:
            f = Path(cartella_lab) / nodo / VISIBILITA.lstrip("/")
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(testo, encoding="utf-8")
        return (f"calendario dei passaggi scritto per {len(destinatari)} nodi: "
                + ", ".join(destinatari))

    def _deposita_visibilita(self, controller: "LabController", inizio: float,
                             finto: bool) -> str:
        if not self.scenario.visibilita:
            return ""
        dati = risolvi_visibilita(self.scenario.visibilita, inizio)
        self._registra("visibilita.json", dati)
        if finto:
            return "calendario dei passaggi non depositato: esecuzione simulata"
        testo = json.dumps(dati)
        destinatari = self._destinatari_visibilita()
        mancati = [n for n in destinatari
                   if not controller.deposita_su(n, VISIBILITA, testo)]
        if mancati:
            return ("calendario dei passaggi non depositato su: "
                    + ", ".join(mancati)
                    + "; contatto continuo")
        return (f"calendario dei passaggi depositato su {len(destinatari)} nodi; "
                "finestre per " + ", ".join(sorted(self.scenario.visibilita)))

    def _apri_finestra(self, controller: "LabController", inizio: float,
                       fine: float, finto: bool) -> str:
        if self.scenario.ramo in ("-", ""):
            return "scenario senza attacco"
        dati = {"ramo": self.scenario.ramo, "conoscenza": self.scenario.conoscenza,
                "inizio": inizio, "fine": fine}
        self._registra("attacco.json", dati)
        descrizione = (f"ramo {self.scenario.ramo}, conoscenza "
                       f"{self.scenario.conoscenza}, {round(fine - inizio, 1)} s")
        if finto:
            return f"finestra d'attacco annotata, non aperta ({descrizione})"
        if controller.deposita_su("attacker", ORDINE_ATTACCO,
                                  json.dumps(dati, ensure_ascii=False)):
            return f"finestra d'attacco aperta: {descrizione}"
        raise RuntimeError(
            f"ordine d'attacco non consegnato al nodo attaccante ({descrizione})")

    def verifica_apparato(self, controller: LabController | None = None
                          ) -> dict:
        cartella_lab = self.prepara()
        controller = controller or LabController(cartella_lab)
        esiti: list[tuple[str, bool, str]] = []
        problema = problema_di_provenienza(codice_del_repository(),
                                           etichetta_dell_immagine())
        esiti.append(("provenienza", problema is None,
                      problema or "immagine coerente con il codice o senza etichetta"))
        esiti.append(("raccolta possibile", controller.modalita == "api-python",
                      "interfaccia Python di Kathará disponibile"
                      if controller.modalita == "api-python" else
                      f"modalità '{controller.modalita}': raccolta finale "
                      "impossibile; interprete con Kathará richiesto "
                      "(.venv/bin/python3)"))
        for algoritmo in self.scenario.trasporto.algoritmi:
            disponibile, esito = carica_algoritmo(algoritmo)
            esiti.append((f"algoritmo {algoritmo}", disponibile, esito))
        try:
            controller.avvia()
            time.sleep(10.0)
            nodo = self._nodo_con_ids()

            atteso = self.scenario.trasporto.algoritmo("ground")
            ok, letto = controller.verifica_trasporto("ground1", atteso)
            esiti.append(("trasporto", ok, f"atteso {atteso}, letto {letto}"))

            visibili = controller.verifica_isolamento(nodo)
            esiti.append(("isolamento", not visibili,
                          "nessun percorso proibito raggiungibile" if not visibili
                          else "raggiungibili: " + ", ".join(visibili)))

            prova = json.dumps({"prova": True, "istante": time.time()})
            consegnato = controller.deposita_su("attacker", ORDINE_ATTACCO, prova)
            esiti.append(("consegna all'attaccante", consegnato,
                          f"scritto e riletto {ORDINE_ATTACCO}" if consegnato
                          else "file non consegnato"))
            controller.esegui_su("attacker", f"rm -f {ORDINE_ATTACCO}")

            consegnato = controller.deposita_su(nodo, ORARIO, prova)
            esiti.append((f"consegna a {nodo}", consegnato,
                          f"scritto e riletto {ORARIO}" if consegnato
                          else "file non consegnato"))
            controller.esegui_su(nodo, f"rm -f {ORARIO}")

            vivi = controller._uscita_di("observer", "pgrep -c tcpdump || echo 0")
            attivo = vivi.strip().splitlines()[-1].strip() not in ("", "0")
            esiti.append(("osservatore", attivo,
                          "tcpdump in esecuzione" if attivo
                          else "tcpdump non in esecuzione"))
        finally:
            try:
                controller.arresta()
            except Exception:
                pass
        return {"laboratorio": str(cartella_lab),
                "controlli": [{"nome": n, "esito": "ok" if o else "GUASTO",
                               "dettaglio": d} for n, o, d in esiti],
                "tutto_a_posto": all(o for _, o, _ in esiti)}

    def conduci(self, controller: LabController | None = None,
                finto: bool = False, ignora_rtt: bool = False,
                ignora_isolamento: bool = False) -> dict:
        cartella_lab = self.prepara()
        chiave = self.config.chiave_profilo()
        impara = (self.profilo_riusato is None
                  and float(self.fasi_effettive.get("nominale", 0) or 0) > 0)
        if impara:
            self.archivio.prenota(chiave, self.run_id)
        else:
            altra = self.archivio.in_apprendimento(chiave)
            if altra is not None:
                raise ProfiloOccupato(chiave, altra)
        controller = controller or LabController(cartella_lab)
        verita = GroundTruthRecorder(self.radice / "truth" / "etichette.jsonl")
        conf = self.config.come_dict()
        conf["profilo_riusato"] = self.profilo_riusato
        verita.configurazione(conf)

        scheduler = PhaseScheduler(self.fasi_effettive)
        if self.motivo_profilo:
            verita.evento(self.motivo_profilo)
        nota_lab = self._scrivi_visibilita_nel_laboratorio(cartella_lab, scheduler.t0)
        if nota_lab:
            verita.evento(nota_lab)
        dormi = (lambda _s: None) if finto else time.sleep
        rtt_ok: bool | None = None
        raccolta_completa = True
        visibilita_caricata: bool | None = None
        if not finto:
            immagine = etichetta_dell_immagine()
            self._aggiungi_a_run_json("immagine", immagine)
            problema = problema_di_provenienza(
                codice_del_repository(), immagine)
            if problema:
                verita.evento(f"provenienza non verificata: {problema}")
                verita.chiudi()
                raise RuntimeError(problema + "; esecuzione annullata")
            for algoritmo in self.scenario.trasporto.algoritmi:
                disponibile, esito = carica_algoritmo(algoritmo)
                verita.evento(f"congestion control: {esito}")
                if not disponibile:
                    verita.chiudi()
                    raise RuntimeError(esito + "; esecuzione annullata")
        try:
            if not finto:
                controller.avvia()
                if self.core:
                    fatti = controller.fissa_core(self.core)
                    if fatti == 0:
                        raise RuntimeError("nessun container del laboratorio per i "
                                           f"core {self.core}")
                    verita.evento(f"core {self.core} assegnati a {fatti} container "
                                  "del laboratorio")
                canale = self.scenario.canale
                atteso_rtt = canale.rtt_atteso_ms
                massimo_rtt = max(canale.rtt_massimo_atteso_ms,
                                  canale.ritardo_massimo_ms
                                  + self.scenario.ritardo_massimo_di("ground1"))
                dichiarato = (
                    f"{atteso_rtt:g}" if massimo_rtt == atteso_rtt
                    else f"fra {atteso_rtt:g} e {massimo_rtt:g}")
                rtt_ok = controller.verifica_rtt(
                    "ground1", "10.0.0.10", atteso_rtt,
                    atteso_massimo_ms=massimo_rtt)
                verita.evento(
                    f"verifica del canale: rtt atteso "
                    f"{dichiarato} ms, esito "
                    f"{'conforme' if rtt_ok else 'non conforme'}")
                if not rtt_ok and not ignora_rtt:
                    raise RuntimeError(
                        "RTT misurato diverso dal dichiarato; esecuzione annullata "
                        "(--ignora-rtt per forzarla)")
                attesi_nodo = tempi_attesi_per_nodo(self.scenario)
                massimi_nodo = tempi_massimi_per_nodo(self.scenario)
                for nodo, atteso_nodo in attesi_nodo.items():
                    massimo_nodo = massimi_nodo.get(nodo, atteso_nodo)
                    ok_nodo = controller.verifica_rtt(
                        nodo, "10.0.0.10", atteso_nodo, campioni=50,
                        assestamento_s=0.0,
                        atteso_massimo_ms=massimo_nodo)
                    dichiarato_nodo = (
                        f"{atteso_nodo:g}" if massimo_nodo == atteso_nodo
                        else f"fra {atteso_nodo:g} e {massimo_nodo:g}")
                    verita.evento(
                        f"verifica del canale di {nodo}: rtt atteso "
                        f"{dichiarato_nodo} ms, "
                        f"esito {'conforme' if ok_nodo else 'non conforme'}")
                    rtt_ok = rtt_ok and ok_nodo
                    if not ok_nodo and not ignora_rtt:
                        raise RuntimeError(
                            f"RTT di {nodo} diverso dal dichiarato; esecuzione "
                            "annullata")
                atteso = self.scenario.trasporto.algoritmo("ground")
                ok_trasporto, effettivo = controller.verifica_trasporto(
                    "ground1", atteso)
                verita.evento(
                    f"verifica del trasporto: atteso {atteso}, osservato "
                    f"{effettivo}, esito {'conforme' if ok_trasporto else 'non conforme'}")
                if (not ok_trasporto and "non misurato" not in effettivo
                        and not ignora_rtt):
                    raise RuntimeError(
                        f"controllo di congestione in uso {effettivo}, atteso "
                        f"{atteso}; esecuzione annullata")
                visibili = controller.verifica_isolamento(
                    self._nodo_con_ids())
                verita.evento(
                    "verifica dell'isolamento: "
                    + ("nessun percorso proibito raggiungibile"
                       if not visibili else
                       "percorsi proibiti raggiungibili: " + ", ".join(visibili)))
                if visibili and not ignora_isolamento:
                    raise RuntimeError(
                        "percorsi proibiti raggiungibili dal nodo dell'IDS: "
                        + ", ".join(visibili)
                        + "; esecuzione annullata (--ignora-isolamento per "
                          "forzarla, risultato non valido)")
            finestra = scheduler.intervallo("attacco")
            primo = True
            for fase in scheduler.scorri(dormi=dormi):
                self._campiona_banco(fase.nome, finto)
                if primo:
                    verita.evento(
                        self._deposita_orario(controller, fase.inizio, finto),
                        fase.inizio)
                    nota_vis = self._deposita_visibilita(controller, fase.inizio,
                                                         finto)
                    if nota_vis:
                        verita.evento(nota_vis, fase.inizio)
                    if finestra is not None:
                        verita.evento(
                            self._apri_finestra(controller, finestra[0],
                                                finestra[1], finto),
                            fase.inizio)
                    primo = False
                verita.fase(fase.nome, "inizio", fase.inizio)
                if fase.nome == "attacco":
                    verita.attacco("inizio", self.scenario.classe, self.scenario.ramo,
                                   self.scenario.conoscenza, fase.inizio)
                    if self.scenario.conoscenza == "esplorativa":
                        verita.ricognizione("inizio", fase.inizio)
                    verita.attacco("fine", self.scenario.classe, self.scenario.ramo,
                                   self.scenario.conoscenza, fase.fine)
                verita.fase(fase.nome, "fine", fase.fine)
        finally:
            if not finto:
                try:
                    self.banco["cpu_nodo_ids"] = leggi_cpu_stat(controller._uscita_di(
                        self._nodo_con_ids(), "cat /sys/fs/cgroup/cpu.stat"))
                except Exception:
                    pass
                nomi = [n.nome for n in nodi_dello_scenario(self.scenario)]
                controller.concludi(nomi)
                try:
                    copiati = controller.raccogli(nomi, self.radice)
                    saltati = getattr(controller, "saltati_in_raccolta", [])
                    raccolta_completa = not saltati
                    verita.evento(
                        f"raccolta dei dati: {len(copiati)} file copiati"
                        + (f", {len(saltati)} non copiati: " + "; ".join(saltati[:3])
                           if saltati else ""))
                    if self.scenario.visibilita:
                        mancanti = nodi_senza_calendario(
                            self.radice, self._destinatari_visibilita())
                        visibilita_caricata = not mancanti
                        verita.evento(
                            "calendario dei passaggi caricato da tutti i nodi"
                            if not mancanti else
                            "calendario dei passaggi non caricato da: "
                            + ", ".join(mancanti)
                            + "; controllo geometrico non misurato")
                    verita.chiudi()
                    self._misura_servizio()
                except Exception as errore:
                    raccolta_completa = False
                    verita.evento(f"raccolta dei dati non riuscita: {errore}")
                controller.arresta()
            verita.chiudi()

        depositato = None if finto else self._deposita_profilo()
        if impara:
            self.archivio.libera(chiave, self.run_id)
        riepilogo = {
            "run_id": self.run_id,
            "scenario": self.scenario.id,
            "chiave_profilo": self.config.chiave_profilo(),
            "fasi": [f.nome for f in scheduler.fasi],
            "durata_prevista_s": scheduler.durata_totale,
            "cartella": str(self.radice),
            "laboratorio": str(cartella_lab),
            "controller": controller.modalita,
            "profilo_riusato": self.profilo_riusato,
            "fase_nominale_saltata": self.profilo_riusato is not None,
            "raccolta_completa": raccolta_completa,
            "visibilita_caricata": visibilita_caricata,
            "profilo_depositato": depositato,
            "rtt_conforme": rtt_ok,
            "laboratorio_hash": hash_del_laboratorio(cartella_lab),
            "banco": self.banco,
        }
        (self.radice / "config" / "riepilogo.json").write_text(
            json.dumps(riepilogo, indent=2, ensure_ascii=False), encoding="utf-8")
        return riepilogo


def suffisso_perdita(perdita: float) -> str:
    return "P" + f"{perdita:g}".replace(".", "")


STRATEGIE_DI_VARIANTE = ("identita_dichiarata", "identita_esplorazione", "imita",
                         "dimensione_comandi", "vittima", "jitter",
                         "forma_sessioni", "distanza_raffiche_s")

VOCI_DI_VARIANTE = ("suffisso", "carico_nominale", "carico_per_stazione",
                    "canali_per_nodo", "canale") + STRATEGIE_DI_VARIANTE


def applica_variante(scenario: ScenarioSpec, percorso: str | Path) -> ScenarioSpec:
    import yaml

    d = yaml.safe_load(Path(percorso).read_text(encoding="utf-8")) or {}
    sconosciute = set(d) - set(VOCI_DI_VARIANTE)
    if sconosciute:
        raise ValueError(f"{percorso}: voci sconosciute {sorted(sconosciute)}")
    if "carico_nominale" in d:
        scenario.carico_nominale = scenario.carico_nominale.con(**d["carico_nominale"])
    if "carico_per_stazione" in d:
        scenario.carico_per_stazione = dict(d["carico_per_stazione"] or {})
    if "canali_per_nodo" in d:
        scenario.canali_per_nodo = dict(d["canali_per_nodo"] or {})
    if "canale" in d:
        scenario.canale = scenario.canale.con(**(d["canale"] or {}))
    for strategia in STRATEGIE_DI_VARIANTE:
        if strategia in d:
            setattr(scenario, strategia, d[strategia])
    suffisso = d.get("suffisso")
    if suffisso and f"-{suffisso}" not in scenario.id:
        scenario.id = f"{scenario.id}-{suffisso}"
    problemi = scenario.valida()
    if problemi:
        raise ValueError(f"{percorso}: " + "; ".join(problemi))
    return scenario


def applica_varianti(scenario: ScenarioSpec, trasporto: str | None = None,
                     perdita: float | None = None,
                     varianti: list[str] | None = None) -> ScenarioSpec:
    for percorso in varianti or ():
        scenario = applica_variante(scenario, percorso)
    if perdita is not None:
        scenario.canale = scenario.canale.con(perdita_pct=float(perdita))
        suffisso = suffisso_perdita(float(perdita))
        if f"-{suffisso}" not in scenario.id:
            scenario.id = f"{scenario.id}-{suffisso}"
    if trasporto:
        scenario.trasporto = TransportProfile.profilo(trasporto)
        suffisso = {"standard": "STD", "bbr3": "BBR3"}.get(trasporto, "BBR")
        if not scenario.id.endswith(f"-{suffisso}"):
            scenario.id = f"{scenario.id}-{suffisso}"
    return scenario


def main() -> None:
    ap = argparse.ArgumentParser(description="Esecuzione di uno scenario")
    ap.add_argument("scenario", help="file YAML dello scenario")
    ap.add_argument("--dati", default="data", help="cartella dei dati delle esecuzioni")
    ap.add_argument("--finto", action="store_true",
                    help="scorre le fasi senza avviare il laboratorio")
    ap.add_argument("--rifai-profilo", action="store_true",
                    help="riapprende il profilo anche se archiviato")
    ap.add_argument("--trasporto", default=None, choices=("bbr", "bbr3", "standard"),
                    help="profilo di trasporto per tutti i nodi")
    ap.add_argument("--ignora-isolamento", action="store_true",
                    help="avvia anche con percorsi proibiti (risultato non valido)")
    ap.add_argument("--ignora-rtt", action="store_true",
                    help="avvio anche con RTT misurato diverso dal dichiarato")
    ap.add_argument("--verifica-apparato", action="store_true",
                    help="avvia il laboratorio, verifica l'apparato sperimentale e lo spegne")
    ap.add_argument("--solo-prepara", action="store_true",
                    help="genera solo lab.conf e i file di avvio")
    ap.add_argument("--run-id", default=None,
                    help="identificativo dell'esecuzione, necessario con più esecuzioni in "
                         "parallelo")
    ap.add_argument("--core", default=None,
                    help="processori da assegnare al laboratorio, per esempio 0-1")
    ap.add_argument("--perdita", type=float, default=None,
                    help="perdita del canale su tutti i nodi, %%")
    ap.add_argument("--variante", action="append", default=[],
                    help="YAML che modifica carico o canali; ripetibile")
    ap.add_argument("--seme", type=int, default=None,
                    help="seme dell'esecuzione, da cui derivano i semi dei nodi")
    args = ap.parse_args()

    scenario = applica_varianti(ScenarioSpec.da_file(args.scenario), args.trasporto,
                                args.perdita, args.variante)
    if args.seme is not None:
        scenario.seme = args.seme
    if args.run_id and (Path(args.dati) / "runs" / args.run_id).exists():
        raise SystemExit(f"l'esecuzione {args.run_id} esiste già")
    esperimento = Experiment(scenario, args.dati, run_id=args.run_id,
                             rifai_profilo=args.rifai_profilo, core=args.core)
    if args.solo_prepara:
        cartella = esperimento.prepara()
        print(f"laboratorio generato in {cartella}")
        return
    if args.verifica_apparato:
        esito = esperimento.verifica_apparato()
        print(json.dumps(esito, indent=2, ensure_ascii=False))
        raise SystemExit(0 if esito["tutto_a_posto"] else 1)
    riepilogo = esperimento.conduci(finto=args.finto, ignora_rtt=args.ignora_rtt,
                                    ignora_isolamento=args.ignora_isolamento)
    print(json.dumps(riepilogo, indent=2, ensure_ascii=False))
    if (not riepilogo.get("raccolta_completa", True)
            or riepilogo.get("visibilita_caricata") is False):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
