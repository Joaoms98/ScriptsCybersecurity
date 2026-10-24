#!/usr/bin/env python3
"""
Varre uma lista de IPs com nmap e imprime no terminal as portas abertas
de cada host, junto com o serviço e versão detectada.

Uso:
    python3 nmap_scan.py ips.txt
    python3 nmap_scan.py ips.txt --fast        # só top-100 portas, sem versão
    python3 nmap_scan.py ips.txt --full        # 1-65535 (demorado)
    python3 nmap_scan.py ips.txt --ports 22,80,443,3306

O arquivo de IPs aceita 1 host por linha (IP, hostname, CIDR como 10.0.0.0/24
ou faixa como 10.0.0.1-50). Linhas em branco e comentários com # são ignoradas.
"""

import argparse
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
GREY = "\033[90m"


def read_file_text(path: Path) -> str:
    # txt criados no Windows (PowerShell >, Set-Content, Notepad) costumam vir
    # em UTF-16 ou com BOM. Detecta pelo BOM e cai pra latin-1 em último caso,
    # pra não estourar UnicodeDecodeError antes de chamar o nmap.
    data = path.read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    for enc in ("utf-8-sig", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def read_targets(path: Path) -> list[str]:
    targets: list[str] = []
    for raw in read_file_text(path).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    if not targets:
        sys.exit(f"{RED}Nenhum alvo válido em {path}{RESET}")
    return targets


def build_cmd(targets: list[str], mode: str, ports: str | None, extra: list[str]) -> list[str]:
    # -Pn      → não assume que o host está down se não responder ping (firewalls)
    # -n       → não resolve DNS reverso (acelera)
    # --open   → mostra só portas abertas no stdout do nmap
    # -T4      → timing agressivo (bom equilíbrio)
    # -sS      → SYN scan (precisa de root; cai pra -sT se não for root)
    # -sV      → version detection
    # -sC      → roda os scripts NSE padrao (equivale a --script=default)
    # --top-ports N → N portas mais comuns
    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    scan_type = "-sS" if is_root else "-sT"

    cmd = ["nmap", scan_type, "-Pn", "-n", "--open", "-T4"]

    if ports:
        cmd += ["-p", ports, "-sC", "-sV"]
    elif mode == "fast":
        cmd += ["--top-ports", "100"]
    elif mode == "full":
        cmd += ["-p-", "-sC", "-sV"]
    else:  # default
        cmd += ["--top-ports", "1000", "-sC", "-sV"]

    cmd += ["-oX", "-"]  # XML no stdout pra parsear
    cmd += extra
    cmd += targets
    return cmd


def parse_and_print(xml_bytes: bytes) -> None:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        sys.exit(f"{RED}Falha ao parsear XML do nmap: {e}{RESET}")

    hosts = root.findall("host")
    if not hosts:
        print(f"{YELLOW}Nenhum host respondeu.{RESET}")
        return

    total_open = 0
    for host in hosts:
        status = host.find("status")
        state = status.get("state") if status is not None else "unknown"

        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "?"

        hostname = ""
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = f" ({hn.get('name')})"

        header_color = GREEN if state == "up" else GREY
        print(f"\n{header_color}{BOLD}▶ {addr}{hostname}  [{state}]{RESET}")

        ports_el = host.find("ports")
        if ports_el is None:
            print(f"  {GREY}sem informação de portas{RESET}")
            continue

        open_ports = [
            p for p in ports_el.findall("port")
            if (p.find("state") is not None and p.find("state").get("state") == "open")
        ]

        if not open_ports:
            print(f"  {GREY}nenhuma porta aberta encontrada{RESET}")
            continue

        print(f"  {BOLD}{'PORTA':<10}{'PROTO':<7}{'SERVIÇO':<16}VERSÃO{RESET}")
        for p in open_ports:
            total_open += 1
            portid = p.get("portid", "?")
            proto = p.get("protocol", "?")
            svc = p.find("service")
            name = svc.get("name", "") if svc is not None else ""
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            extrainfo = svc.get("extrainfo", "") if svc is not None else ""
            version_str = " ".join(x for x in (product, version, extrainfo) if x)
            print(f"  {CYAN}{portid:<10}{RESET}{proto:<7}{name:<16}{version_str}")

    print(f"\n{BOLD}Resumo:{RESET} {len(hosts)} host(s), {total_open} porta(s) aberta(s).")


def main() -> None:
    ap = argparse.ArgumentParser(description="Scanner nmap em lote a partir de um txt de IPs.")
    ap.add_argument("file", type=Path, help="arquivo com um alvo por linha")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--fast", action="store_true", help="top 100 portas, sem versão")
    group.add_argument("--full", action="store_true", help="todas as 65535 portas (lento)")
    group.add_argument("--ports", help="lista explícita, ex: 22,80,443 ou 1-1024")
    ap.add_argument("--extra", nargs=argparse.REMAINDER, default=[],
                    help="argumentos extras passados direto ao nmap")
    args = ap.parse_args()

    if shutil.which("nmap") is None:
        sys.exit(f"{RED}nmap não encontrado no PATH. Instale com: winget install Insecure.Nmap{RESET}")

    if not args.file.is_file():
        sys.exit(f"{RED}Arquivo não encontrado: {args.file}{RESET}")

    targets = read_targets(args.file)
    mode = "fast" if args.fast else "full" if args.full else "default"
    cmd = build_cmd(targets, mode, args.ports, args.extra)

    print(f"{GREY}$ {' '.join(cmd[:-len(targets)])} <{len(targets)} alvo(s)>{RESET}")
    print(f"{GREY}  alvos: {', '.join(targets[:5])}{'...' if len(targets) > 5 else ''}{RESET}")
    print(f"{GREY}  (isso pode levar alguns minutos){RESET}")

    try:
        proc = subprocess.run(cmd, capture_output=True, check=False)
    except FileNotFoundError:
        sys.exit(f"{RED}nmap sumiu do PATH no meio da execução.{RESET}")
    except KeyboardInterrupt:
        sys.exit(f"\n{YELLOW}Interrompido.{RESET}")

    if proc.returncode != 0 and not proc.stdout:
        stderr = proc.stderr.decode(errors="replace").strip()
        sys.exit(f"{RED}nmap falhou (exit {proc.returncode}): {stderr}{RESET}")

    parse_and_print(proc.stdout)


if __name__ == "__main__":
    main()
