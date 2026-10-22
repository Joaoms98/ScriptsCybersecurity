#!/usr/bin/env python3
"""Le uma lista de subdominios e mostra apenas os que estao de pe."""

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 2xx/3xx = respondendo normalmente; 401/403/405 = servidor ativo, mas bloqueando o acesso
DEFAULT_CODES = "200-299,300-399,401,403,405"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0 Safari/537.36"
}


def parse_codes(spec):
    codes = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            codes.update(range(int(start), int(end) + 1))
        elif part:
            codes.add(int(part))
    return codes


def read_hosts(path):
    hosts = []
    seen = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            host = line.strip()
            if not host or host.startswith("#"):
                continue
            # aceita linhas com http(s):// e caminho, fica so com o host
            host = host.split("://", 1)[-1].split("/", 1)[0].lower()
            if host not in seen:
                seen.add(host)
                hosts.append(host)
    return hosts


def check(host, timeout):
    """Tenta HTTPS e depois HTTP. Retorna (url, status, location) ou None."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            resp = requests.get(
                url,
                headers=HEADERS,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                stream=True,  # nao baixa o corpo da resposta
            )
            resp.close()
            return url, resp.status_code, resp.headers.get("Location", "")
        except requests.RequestException:
            continue
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("arquivo", help="arquivo com um subdominio por linha")
    parser.add_argument("-o", "--output", help="salva os ativos neste arquivo")
    parser.add_argument("-t", "--threads", type=int, default=30, help="requisicoes simultaneas (padrao: 30)")
    parser.add_argument("--timeout", type=float, default=8, help="timeout em segundos (padrao: 8)")
    parser.add_argument("-c", "--codes", default=DEFAULT_CODES, help=f"status aceitos (padrao: {DEFAULT_CODES})")
    args = parser.parse_args()

    accepted = parse_codes(args.codes)
    hosts = read_hosts(args.arquivo)
    print(f"[*] {len(hosts)} subdominios para testar", file=sys.stderr)

    alive = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check, h, args.timeout): h for h in hosts}
        for done, future in enumerate(as_completed(futures), 1):
            result = future.result()
            if result and result[1] in accepted:
                url, status, location = result
                line = f"{url} [{status}]" + (f" -> {location}" if location else "")
                print("\r\033[K", end="", file=sys.stderr)  # limpa a linha de progresso
                print(line, flush=True)
                alive.append(line)
            print(f"\r[*] {done}/{len(hosts)}", end="", file=sys.stderr, flush=True)

    print(f"\n[+] {len(alive)} ativos de {len(hosts)}", file=sys.stderr)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write("\n".join(alive) + ("\n" if alive else ""))
        print(f"[+] salvo em {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
