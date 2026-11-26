from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from model.config import CO_RESIDENTE, NodeSpec, Ruolo, ScenarioSpec

IMMAGINE_BASE = "cyberrange/base:0.1"
DOMINIO = "RADIO"
PORTA_TCTM = 5000

PROFILO_NEL_LAB = "/shared/profilo.json"
STATO_ALLARME = "/dati/local/stato_allarme.json"
ORARIO = "/dati/orario.json"

VISIBILITA = "/dati/visibilita.json"

ARCHIVIO_BORDO = "/dati/bordo"
LIMITE_ARCHIVIO_MB = 64.0

ORDINE_ATTACCO = "/dati/attacco.json"


def seme_di(seme: int | None, nodo: str) -> int | None:
    if seme is None:
        return None
    impronta = hashlib.sha256(f"{seme}:{nodo}".encode("utf-8")).hexdigest()
    return int(impronta[:8], 16) & 0x7FFFFFFF


def _argomento_seme(s: ScenarioSpec, nodo: str) -> str:
    seme = seme_di(s.seme, nodo)
    return "" if seme is None else f"--seme {seme} "


def _argomenti_carico(c: WorkloadProfile) -> str:
    composizione = ",".join(f"{k}={v:g}" for k, v in sorted(c.composizione.items()))
    return (f"--comandi-al-minuto {c.comandi_al_minuto:g} --variabilita {c.variabilita:g} "
            f"--durata-sessione {c.durata_sessione_s:g} "
            f"--variabilita-sessione {c.variabilita_sessione:g} "
            f"--pausa-fra-sessioni {c.pausa_fra_sessioni_s:g} "
            f"--composizione '{composizione}' "
            f"--telemetria-kb {c.telemetria_kb:g} --telemetria-ogni {c.telemetria_ogni_s:g}")


def _comando_ids(s: ScenarioSpec, vista: str, punto: str,
                 profilo: str | None, chiave: str | None = None) -> str:
    parti = [f"python3 -m ids.engine --vista {vista}",
             "--allarmi /dati/local/allarmi.jsonl",
             f"--punto-di-cattura '{punto}'",
             f"--stato-allarme {STATO_ALLARME}",
             f"--totale {sum(s.fasi.values())}",
             f"--ritardo-avvio {s.fasi.get('avvio', 0)}",
             f"--orario {ORARIO}",
             "--riepilogo /dati/local/riepilogo_ids.json"]
    if chiave:
        parti.append(f"--chiave-profilo '{chiave}'")
    if profilo:
        parti.append(f"--profilo {profilo}")
    else:
        parti.append(f"--nominale {s.fasi.get('nominale', 900)}")
        parti.append("--salva-profilo /dati/local/profilo")
    return " ".join(parti) + " &"


def nodi_dello_scenario(s: ScenarioSpec) -> list[NodeSpec]:
    nodi: list[NodeSpec] = [
        NodeSpec(nome="satellite", ruolo=Ruolo.SATELLITE, immagine=IMMAGINE_BASE,
                 indirizzo="10.0.0.10/24",
                 memoria="512m", cpu=0.5,
                 sysctl=(f"net.ipv4.tcp_congestion_control={s.trasporto.algoritmo('satellite')}",)),
    ]
    for i in range(1, s.ground_unit + 1):
        nodi.append(NodeSpec(
            nome=f"ground{i}", ruolo=Ruolo.GROUND, immagine=IMMAGINE_BASE,
            indirizzo=f"10.0.0.{20 + i}/24",
            sysctl=(f"net.ipv4.tcp_congestion_control={s.trasporto.algoritmo('ground')}",)))
    nodi.append(NodeSpec(
        nome="attacker", ruolo=Ruolo.ATTACKER, immagine=IMMAGINE_BASE,
        indirizzo="10.0.0.40/24",
        sysctl=(f"net.ipv4.tcp_congestion_control={s.trasporto.algoritmo('attacker')}",)))
    nodi.append(NodeSpec(nome="observer", ruolo=Ruolo.OBSERVER, immagine=IMMAGINE_BASE,
                         indirizzo="10.0.0.50/24"))
    return nodi


def genera_lab_conf(s: ScenarioSpec, nodi: list[NodeSpec] | None = None) -> str:
    nodi = nodi or nodi_dello_scenario(s)
    righe = [
        f'LAB_DESCRIPTION="Banco satellite-ground, scenario {s.id}"',
        'LAB_VERSION="0.1"',
        'LAB_AUTHOR="tirocinio"',
        "",
        f"# canale: {s.canale.nome}, ritardo {s.canale.ritardo_ms} ms, "
        f"perdita {s.canale.perdita_pct}%",
        f"# trasporto: {s.trasporto.nome} (predefinito {s.trasporto.predefinito})",
        f"# punto di cattura dell'IDS: {s.punto_di_cattura}",
        "",
    ]
    for n in nodi:
        righe.append(f"# {n.nome} ({n.ruolo})")
        for i, dominio in enumerate(n.domini):
            righe.append(f"{n.nome}[{i}]={dominio}")
        righe.append(f'{n.nome}[image]="{n.immagine}"')
        if n.memoria:
            righe.append(f"{n.nome}[mem]={n.memoria}")
        if n.cpu:
            righe.append(f"{n.nome}[cpus]={n.cpu}")
        for voce in n.sysctl:
            righe.append(f'{n.nome}[sysctl]="{voce}"')
        righe.append("")
    return "\n".join(righe)


def comando_netem(s: ScenarioSpec, interfaccia: str = "eth0",
                  nodo: str | None = None, modello: bool = False) -> str:
    c = s.canale if nodo in (None, "satellite") else s.canale_di(nodo)
    limite = c.limite_coda_pacchetti()
    verbo = "change" if modello else "replace"
    ritardo = "{ritardo}" if modello else f"{c.ritardo_ms}"
    return (f"tc qdisc {verbo} dev {interfaccia} root netem "
            f"delay {ritardo}ms {c.jitter_ms}ms "
            f"loss {c.perdita_pct}% "
            f"rate {c.banda_mbit}mbit "
            f"limit {limite}")


def genera_startup(s: ScenarioSpec, n: NodeSpec,
                   profilo: str | None = None, chiave: str | None = None) -> str:
    righe = ["#!/bin/sh", "set -e"]
    if n.indirizzo:
        righe.append(f"ip address add {n.indirizzo} dev eth0")
    righe.append("ip link set eth0 up")
    if n.ruolo in (Ruolo.SATELLITE, Ruolo.GROUND, Ruolo.ATTACKER):
        righe.append(comando_netem(s, nodo=n.nome))
    if n.ruolo == Ruolo.SATELLITE:
        righe += s.canale.comandi_strozzatura()
    righe.append("mkdir -p /dati/local")
    righe.append(f"exec 2>> /dati/local/{n.nome}.err")
    vista = f"/dati/local/{n.nome}.jsonl"

    if n.ruolo in (Ruolo.SATELLITE, Ruolo.GROUND, Ruolo.ATTACKER) and s.canale.si_riconfigura:
        c = s.canale if n.nome == "satellite" else s.canale_di(n.nome)
        modello = comando_netem(s, nodo=n.nome, modello=True)
        righe.append(
            f"python3 -m common.riconfigurazione --modello '{modello}' "
            f"--minimo-ms {c.ritardo_ms:g} "
            f"--massimo-ms {c.riconfigurazione_ritardo_max_ms:g} "
            f"--durata-s {c.riconfigurazione_s or s.canale.riconfigurazione_s:g} "
            f"--forma {c.forma_riconfigurazione or s.canale.forma_riconfigurazione} "
            f"{_argomento_seme(s, n.nome)}--vista {vista} &")

    if n.ruolo == Ruolo.GROUND and n.nome in (s.visibilita or {}):
        c = s.canale_di(n.nome)
        if c.varia_nella_finestra:
            modello = comando_netem(s, nodo=n.nome, modello=True)
            righe.append(
                f"python3 -m common.andamento_rtt --modello '{modello}' "
                f"--stazione {n.nome} --visibilita {VISIBILITA} "
                f"--forma {c.andamento_rtt} --minimo-ms {c.ritardo_ms:g} "
                f"--massimo-ms {c.ritardo_ai_bordi_ms:g} --vista {vista} &")

    vis = f" --visibilita {VISIBILITA}" if s.visibilita else ""

    match n.ruolo:
        case Ruolo.SATELLITE:
            righe += [
                f"python3 -m app.satellite --vista {vista} --porta {PORTA_TCTM} "
                f"--archivio {ARCHIVIO_BORDO} --limite-mb {LIMITE_ARCHIVIO_MB:g} "
                f"--stato-allarme {STATO_ALLARME}{vis} &",
                f"python3 -m sensor.sensor --vista {vista} --archivio {ARCHIVIO_BORDO} "
                f"--capacita-archivio-mb {LIMITE_ARCHIVIO_MB:g} &",
            ]
            if s.punto_di_cattura == CO_RESIDENTE:
                righe.append(_comando_ids(s, vista, CO_RESIDENTE, profilo, chiave))
        case Ruolo.GROUND:
            righe += [
                f"python3 -m sensor.sensor --vista {vista} &",
                f"python3 -m app.ground --satellite 10.0.0.10 --porta {PORTA_TCTM} "
                f"--vista {vista} {_argomenti_carico(s.carico_di(n.nome))} "
                f"{_argomento_seme(s, n.nome)}"
                f"--congestione {s.trasporto.algoritmo('ground')} "
                f"--identita {n.nome}{vis} &",
            ]
        case Ruolo.ATTACKER:
            righe += [
                f"python3 -m sensor.sensor --vista {vista} &",
                f"python3 -m app.attacker --vista {vista} --satellite 10.0.0.10 "
                f"--porta {PORTA_TCTM} --ramo '{s.ramo}' "
                f"--conoscenza '"
                f"{s.conoscenza if s.conoscenza in ('informata', 'esplorativa') else 'informata'}' "
                f"--identita-bersaglio {s.identita_attaccante or 'ground1'} "
                f"{_argomento_seme(s, n.nome)}"
                f"--comandi-al-minuto {s.carico_nominale.comandi_al_minuto} "
                f"--congestione {s.trasporto.algoritmo('attacker')} "
                f"--pazienza {s.pazienza} "
                f"--identita-dichiarata {s.identita_dichiarata} "
                f"--identita-esplorazione {s.identita_esplorazione} "
                f"--imita {s.imita} "
                f"--dimensione-comandi {s.dimensione_comandi} "
                f"--vittima '{s.vittima}' "
                f"--jitter {s.jitter} "
                f"--variabilita {s.carico_nominale.variabilita:g} "
                f"--forma-sessioni {s.forma_sessioni} "
                f"--distanza-raffiche {s.distanza_raffiche_s:g} "
                f"--durata-sessione {s.carico_nominale.durata_sessione_s:g} "
                f"--pausa-sessione {s.carico_nominale.pausa_fra_sessioni_s:g} "
                f"--variabilita-sessione {s.carico_nominale.variabilita_sessione:g} "
                f"--ritmo-nominale {s.ground_unit * s.carico_nominale.comandi_al_minuto / 60.0:g} "
                f"--ordine {ORDINE_ATTACCO} &",
            ]
        case Ruolo.OBSERVER:
            righe += [
                f"python3 -m sensor.sensor --vista {vista} --senza-bordo &",
                "python3 -m observer.observer --interfaccia eth0 "
                "--uscita /dati/omniscient/radio.pcap &",
            ]
    righe.append("sleep infinity")
    return "\n".join(righe) + "\n"


def scrivi_laboratorio(s: ScenarioSpec, cartella: str | Path,
                       profilo: str | None = None, chiave: str | None = None) -> Path:
    d = Path(cartella)
    d.mkdir(parents=True, exist_ok=True)
    (d / "shared").mkdir(exist_ok=True)
    if profilo:
        shutil.copyfile(profilo, d / "shared" / Path(PROFILO_NEL_LAB).name)
        profilo = PROFILO_NEL_LAB
    nodi = nodi_dello_scenario(s)
    (d / "lab.conf").write_text(genera_lab_conf(s, nodi), encoding="utf-8")
    for n in nodi:
        (d / f"{n.nome}.startup").write_text(genera_startup(s, n, profilo, chiave),
                                             encoding="utf-8")
    (d / "shared").mkdir(exist_ok=True)
    return d
