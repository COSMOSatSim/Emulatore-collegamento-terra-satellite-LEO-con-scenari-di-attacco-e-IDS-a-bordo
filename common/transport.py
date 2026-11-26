from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
from dataclasses import dataclass

TCP_CONGESTION = getattr(socket, "TCP_CONGESTION", 13)
E_LINUX = platform.system() == "Linux"


@dataclass(frozen=True)
class EsitoTrasporto:
    richiesto: str
    effettivo: str | None
    applicato: bool
    motivo: str = ""

    @property
    def coerente(self) -> bool:
        return self.applicato and self.effettivo == self.richiesto


def imposta_congestione(sock: socket.socket, algoritmo: str) -> EsitoTrasporto:
    if not E_LINUX:
        return EsitoTrasporto(algoritmo, None, False, "sistema non Linux: nessun effetto")
    try:
        sock.setsockopt(socket.IPPROTO_TCP, TCP_CONGESTION, algoritmo.encode())
    except OSError as e:
        return EsitoTrasporto(algoritmo, leggi_congestione(sock), False, f"{e.__class__.__name__}: {e}")
    return EsitoTrasporto(algoritmo, leggi_congestione(sock), True)


def leggi_congestione(sock: socket.socket) -> str | None:
    if not E_LINUX:
        return None
    try:
        grezzo = sock.getsockopt(socket.IPPROTO_TCP, TCP_CONGESTION, 32)
        return grezzo.split(b"\x00", 1)[0].decode(errors="replace") or None
    except OSError:
        return None


def algoritmi_disponibili() -> list[str]:
    try:
        with open("/proc/sys/net/ipv4/tcp_available_congestion_control", encoding="utf-8") as f:
            return f.read().split()
    except OSError:
        return []


def algoritmi_permessi() -> list[str]:
    try:
        with open("/proc/sys/net/ipv4/tcp_allowed_congestion_control", encoding="utf-8") as f:
            return f.read().split()
    except OSError:
        return []


def diagnosi_bbr() -> dict[str, object]:
    disponibili = algoritmi_disponibili()
    permessi = algoritmi_permessi()
    return {
        "linux": E_LINUX,
        "disponibili": disponibili,
        "permessi": permessi,
        "bbr_disponibile": "bbr" in disponibili,
        "bbr_permesso": "bbr" in permessi,
        "pronto": E_LINUX and "bbr" in disponibili and "bbr" in permessi,
    }


def modulo_di(algoritmo: str) -> str:
    return f"tcp_{algoritmo}"


def modulo_presente(algoritmo: str) -> bool:
    if not E_LINUX or shutil.which("modinfo") is None:
        return False
    esito = subprocess.run(["modinfo", modulo_di(algoritmo)], capture_output=True, text=True)
    return esito.returncode == 0


def carica_algoritmo(algoritmo: str) -> tuple[bool, str]:
    if not E_LINUX:
        return True, "sistema non Linux: verifica non eseguita"
    if algoritmo in algoritmi_disponibili():
        return True, f"{algoritmo} disponibile"
    modulo = modulo_di(algoritmo)
    if not modulo_presente(algoritmo):
        return False, f"{algoritmo} non disponibile: modulo {modulo} assente nel sistema"
    comandi = [["modprobe", modulo]]
    if os.geteuid() != 0 and shutil.which("sudo") is not None:
        comandi.append(["sudo", "-n", "modprobe", modulo])
    for comando in comandi:
        if shutil.which(comando[0]) is None:
            continue
        subprocess.run(comando, capture_output=True, text=True)
        if algoritmo in algoritmi_disponibili():
            return True, f"{algoritmo} caricato con {' '.join(comando)}"
    return False, (f"{algoritmo} non disponibile: caricamento di {modulo} non riuscito "
                   f"(sudo modprobe {modulo})")


def crea_socket_client(indirizzo: str, porta: int, algoritmo: str,
                       timeout: float = 10.0) -> tuple[socket.socket, EsitoTrasporto]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    esito = imposta_congestione(sock, algoritmo)
    sock.connect((indirizzo, porta))
    return sock, EsitoTrasporto(esito.richiesto, leggi_congestione(sock),
                                esito.applicato, esito.motivo)
