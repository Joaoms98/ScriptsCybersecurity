#!/usr/bin/env python3
"""
Nuclei vulnerability scanner wrapper.
Lê uma lista de domínios de um arquivo .txt e roda o nuclei contra todos,
mostrando o resultado de forma clara e organizada no terminal.

Uso:
    python3 nuclei_scan.py <arquivo_dominios.txt>
    python3 nuclei_scan.py dominios.txt -s critical,high
    python3 nuclei_scan.py dominios.txt -o resultado.json
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


TEMPLATE_CANDIDATES = [
    Path.home() / "nuclei-templates",
    Path.home() / ".local/nuclei-templates",
    Path("/root/nuclei-templates"),
    Path("/usr/share/nuclei-templates"),
    Path("/opt/nuclei-templates"),
]


# ANSI colors
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"


SEVERITY_COLORS = {
    "critical": C.BG_RED + C.WHITE + C.BOLD,
    "high": C.RED + C.BOLD,
    "medium": C.YELLOW + C.BOLD,
    "low": C.BLUE,
    "info": C.CYAN,
    "unknown": C.DIM,
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def banner():
    print(f"{C.CYAN}{C.BOLD}")
    print("=" * 70)
    print("  NUCLEI SCANNER - Varredura de Vulnerabilidades")
    print("=" * 70)
    print(f"{C.RESET}")


def check_nuclei():
    if shutil.which("nuclei") is None:
        print(f"{C.RED}[!] nuclei não encontrado no PATH.{C.RESET}")
        sys.exit(1)


def find_templates(user_path: Path | None) -> Path:
    """Retorna o diretório de templates. Se não existir, tenta baixar."""
    if user_path:
        if user_path.is_dir():
            return user_path
        print(f"{C.RED}[!] Templates não encontrados em {user_path}{C.RESET}")
        sys.exit(1)

    for p in TEMPLATE_CANDIDATES:
        if p.is_dir() and any(p.iterdir()):
            return p

    print(f"{C.YELLOW}[!] Templates nuclei não encontrados. Rodando -update-templates...{C.RESET}")
    subprocess.run(["nuclei", "-update-templates", "-silent"], check=False)
    for p in TEMPLATE_CANDIDATES:
        if p.is_dir() and any(p.iterdir()):
            return p

    print(f"{C.RED}[!] Não foi possível localizar os templates após o update.{C.RESET}")
    sys.exit(1)


def read_targets(path: Path) -> list[str]:
    if not path.is_file():
        print(f"{C.RED}[!] Arquivo não encontrado: {path}{C.RESET}")
        sys.exit(1)
    targets = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            targets.append(line)
    if not targets:
        print(f"{C.RED}[!] Nenhum domínio válido em {path}{C.RESET}")
        sys.exit(1)
    return targets


def run_nuclei(targets_file: Path, templates_dir: Path, severity: str,
               rate: int, concurrency: int, extra_args: list[str]) -> list[dict]:
    """
    Roda o nuclei com saída JSON e retorna a lista de findings.
    """
    cmd = [
        "nuclei",
        "-list", str(targets_file),
        "-t", str(templates_dir),
        "-severity", severity,
        "-jsonl",                  # saída estruturada em JSON por linha
        "-silent",                 # só os findings no stdout
        "-stats",                  # estatística no stderr
        "-rate-limit", str(rate),
        "-concurrency", str(concurrency),
        "-timeout", "10",
        "-retries", "2",
        "-no-color",
        "-disable-update-check",
    ]
    cmd.extend(extra_args)

    print(f"{C.DIM}[*] Comando: {' '.join(cmd)}{C.RESET}\n")
    print(f"{C.YELLOW}[*] Scan em andamento... (stats aparecem abaixo){C.RESET}\n")

    findings: list[dict] = []
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.append(finding)
            print_finding_live(finding)

        proc.wait()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Scan interrompido pelo usuário.{C.RESET}")

    return findings


def print_finding_live(f: dict):
    info = f.get("info", {})
    sev = (info.get("severity") or "unknown").lower()
    color = SEVERITY_COLORS.get(sev, C.WHITE)
    name = info.get("name", f.get("template-id", "?"))
    url = f.get("matched-at") or f.get("host", "?")
    tid = f.get("template-id", "?")

    tag = f"{color} {sev.upper():^8} {C.RESET}"
    print(f"{tag} {C.BOLD}{name}{C.RESET}")
    print(f"           {C.CYAN}{url}{C.RESET}")
    print(f"           {C.DIM}template: {tid}{C.RESET}\n")


def summarize(findings: list[dict]):
    print(f"\n{C.CYAN}{C.BOLD}" + "=" * 70)
    print("  RESUMO DO SCAN")
    print("=" * 70 + f"{C.RESET}\n")

    if not findings:
        print(f"{C.GREEN}[✓] Nenhuma vulnerabilidade encontrada.{C.RESET}\n")
        return

    by_sev: dict[str, list[dict]] = defaultdict(list)
    by_host: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        sev = (f.get("info", {}).get("severity") or "unknown").lower()
        host = f.get("host") or f.get("matched-at") or "?"
        by_sev[sev].append(f)
        by_host[host].append(f)

    # Totais por severidade
    print(f"{C.BOLD}Total por severidade:{C.RESET}")
    for sev in SEVERITY_ORDER:
        items = by_sev.get(sev, [])
        if not items:
            continue
        color = SEVERITY_COLORS.get(sev, C.WHITE)
        print(f"  {color} {sev.upper():^8} {C.RESET}  {len(items)}")
    print(f"  {C.BOLD}TOTAL{C.RESET}      {len(findings)}\n")

    # Hosts mais afetados
    print(f"{C.BOLD}Hosts mais afetados:{C.RESET}")
    ranked = sorted(by_host.items(), key=lambda kv: -len(kv[1]))[:10]
    for host, items in ranked:
        print(f"  {C.CYAN}{host:<50}{C.RESET} {len(items)} finding(s)")
    print()

    # Detalhamento por severidade (crítico/alto primeiro)
    for sev in SEVERITY_ORDER:
        items = by_sev.get(sev, [])
        if not items:
            continue
        color = SEVERITY_COLORS.get(sev, C.WHITE)
        print(f"{color} {sev.upper()} {C.RESET} {C.BOLD}({len(items)}){C.RESET}")
        print(C.DIM + "-" * 70 + C.RESET)
        for f in items:
            info = f.get("info", {})
            name = info.get("name", "?")
            url = f.get("matched-at") or f.get("host", "?")
            tid = f.get("template-id", "?")
            desc = (info.get("description") or "").strip().split("\n")[0][:120]
            print(f"  • {C.BOLD}{name}{C.RESET}")
            print(f"      {C.CYAN}{url}{C.RESET}")
            print(f"      {C.DIM}template: {tid}{C.RESET}")
            if desc:
                print(f"      {desc}")
            refs = info.get("reference") or []
            if isinstance(refs, list) and refs:
                print(f"      {C.DIM}ref: {refs[0]}{C.RESET}")
        print()


def save_output(findings: list[dict], out_path: Path):
    out_path.write_text(
        json.dumps(findings, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"{C.GREEN}[✓] Resultado salvo em {out_path}{C.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Scanner Nuclei a partir de uma lista de domínios.",
    )
    parser.add_argument("file", type=Path, help="Arquivo .txt com os domínios (um por linha)")
    parser.add_argument("-s", "--severity",
                        default="critical,high,medium,low",
                        help="Severidades a reportar (padrão: critical,high,medium,low)")
    parser.add_argument("-r", "--rate", type=int, default=150,
                        help="Rate limit de requests por segundo (padrão: 150)")
    parser.add_argument("-c", "--concurrency", type=int, default=25,
                        help="Templates concorrentes (padrão: 25)")
    parser.add_argument("-o", "--output", type=Path,
                        help="Salvar findings em JSON")
    parser.add_argument("-t", "--templates", type=Path, default=None,
                        help="Diretório de templates do nuclei (auto-detecta se omitido)")
    parser.add_argument("--extra", nargs=argparse.REMAINDER, default=[],
                        help="Argumentos extras passados ao nuclei (use após --)")
    args = parser.parse_args()

    banner()
    check_nuclei()
    templates_dir = find_templates(args.templates)

    targets = read_targets(args.file)
    print(f"{C.GREEN}[+] {len(targets)} alvo(s) carregados de {args.file}{C.RESET}")
    print(f"{C.GREEN}[+] Templates: {templates_dir}{C.RESET}")
    print(f"{C.GREEN}[+] Severidades: {args.severity}{C.RESET}")
    print(f"{C.GREEN}[+] Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}\n")

    start = datetime.now()
    findings = run_nuclei(
        targets_file=args.file,
        templates_dir=templates_dir,
        severity=args.severity,
        rate=args.rate,
        concurrency=args.concurrency,
        extra_args=args.extra,
    )
    elapsed = datetime.now() - start

    summarize(findings)
    print(f"{C.DIM}Tempo total: {elapsed}{C.RESET}")

    if args.output:
        save_output(findings, args.output)


if __name__ == "__main__":
    main()
