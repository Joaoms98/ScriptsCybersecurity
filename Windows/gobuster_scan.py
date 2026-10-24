#!/usr/bin/env python3
"""
Gobuster scan runner - roda gobuster dir em uma lista de dominios/urls
lidos de um arquivo .txt, com escolha interativa de wordlist e stack.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# SecLists: usa a variavel de ambiente SECLISTS se definida, senao assume
# a copia dentro do proprio projeto (WordLists/SecLists ao lado do script).
SECLISTS_BASE = Path(
    os.environ.get("SECLISTS")
    or (Path(__file__).resolve().parent / "WordLists" / "SecLists")
)
WEBCONTENT = SECLISTS_BASE / "Discovery" / "Web-Content"

# Wordlists genericas por tamanho
SIZE_WORDLISTS = {
    "1": ("small",  WEBCONTENT / "common.txt"),
    "2": ("medium", WEBCONTENT / "raft-medium-directories.txt"),
    "3": ("big",    WEBCONTENT / "big.txt"),
    "4": ("huge",   WEBCONTENT / "DirBuster-2007_directory-list-2.3-big.txt"),
    "5": ("raft-large", WEBCONTENT / "raft-large-directories.txt"),
}

# Wordlists especificas por linguagem/stack
LANG_WORDLISTS = {
    "1":  ("PHP",         WEBCONTENT / "Programming-Language-Specific" / "PHP.fuzz.txt",
           ["php", "html", "txt"]),
    "2":  ("ASP.NET",     WEBCONTENT / "Programming-Language-Specific" / "ASP.NET" / "CommonBackdoors-ASP.fuzz.txt",
           ["asp", "aspx", "config"]),
    "3":  ("Java/JSP",    WEBCONTENT / "Programming-Language-Specific" / "CommonBackdoors-JSP.fuzz.txt",
           ["jsp", "do", "action"]),
    "4":  ("Java Spring", WEBCONTENT / "Programming-Language-Specific" / "Java-Spring-Boot.txt",
           ["jsp", "do"]),
    "5":  ("Golang",      WEBCONTENT / "Programming-Language-Specific" / "golang.txt",
           ["go"]),
    "6":  ("Ruby on Rails", WEBCONTENT / "Programming-Language-Specific" / "ror.txt",
           ["rb"]),
    "7":  ("Perl",        WEBCONTENT / "Programming-Language-Specific" / "CommonBackdoors-PL.fuzz.txt",
           ["pl", "cgi"]),
    "8":  ("Wordpress",   WEBCONTENT / "CMS" / "wordpress.fuzz.txt",
           ["php"]),
    "9":  ("Drupal",      WEBCONTENT / "CMS" / "Drupal.txt",
           ["php"]),
    "10": ("Django",      WEBCONTENT / "CMS" / "Django.txt",
           ["py"]),
    "11": ("Sharepoint",  WEBCONTENT / "CMS" / "Sharepoint.txt",
           ["aspx"]),
    "12": ("Nenhuma (so wordlist generica)", None, []),
}

DEFAULT_STATUS = "200,204,301,302,307,401,403,405"


def read_file_text(path):
    # txt criados no Windows (PowerShell >, Set-Content, Notepad) costumam vir
    # em UTF-16 ou com BOM. Detecta pelo BOM e cai pra latin-1 em ultimo caso,
    # pra nao ler lixo (com errors="ignore" os \x00 entram no meio das linhas).
    data = Path(path).read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    for enc in ("utf-8-sig", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def ask(prompt, default=None):
    tail = f" [{default}]" if default else ""
    r = input(f"{prompt}{tail}: ").strip()
    return r or (default or "")


def choose(title, mapping, show_path=True):
    print(f"\n== {title} ==")
    for k, v in mapping.items():
        name = v[0]
        path = v[1]
        extra = f"  -> {path}" if show_path and path else ""
        print(f"  {k}) {name}{extra}")
    while True:
        c = input("Escolha: ").strip()
        if c in mapping:
            return mapping[c]
        print("Opcao invalida.")


def normalize_target(line):
    t = line.strip()
    if not t or t.startswith("#"):
        return None
    if not t.startswith(("http://", "https://")):
        t = "http://" + t
    return t.rstrip("/")


def safe_name(url):
    return (url.replace("https://", "")
               .replace("http://", "")
               .replace("/", "_")
               .replace(":", "_"))


def run_gobuster(target, wordlist, extensions, status, exclude_length,
                 threads, timeout, extra_args):
    cmd = [
        "gobuster", "dir",
        "-u", target,
        "-w", str(wordlist),
        "-t", str(threads),
        "-s", status,
        "-b", "",
        "--timeout", f"{timeout}s",
        "--no-error",
    ]
    if extensions:
        cmd += ["-x", ",".join(extensions)]
    if exclude_length:
        cmd += ["--exclude-length", exclude_length]
    cmd += extra_args

    print(f"\n[+] {target}")
    print(f"    -> {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        print("\n[!] Interrompido pelo usuario. Pulando para o proximo alvo.")


def main():
    p = argparse.ArgumentParser(description="Roda gobuster dir em uma lista de dominios.")
    p.add_argument("file", nargs="?", help="arquivo .txt com um dominio/URL por linha")
    p.add_argument("--threads", type=int, default=40)
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--status", default=DEFAULT_STATUS,
                   help=f"codigos de status (default: {DEFAULT_STATUS})")
    p.add_argument("--exclude-length", "-xl", default=None,
                   help="tamanhos de resposta a ignorar, ex: 323 ou 323,1024,0-50")
    p.add_argument("--extra", default="",
                   help="argumentos extras para o gobuster entre aspas, ex: --extra='-k -r'")
    args = p.parse_args()

    if not shutil.which("gobuster"):
        sys.exit("[!] gobuster nao esta no PATH. Use o binario em tools/ ou adicione-o ao PATH.")

    if not SECLISTS_BASE.exists():
        sys.exit(f"[!] SecLists nao encontrado em {SECLISTS_BASE}")

    target_file = args.file or ask("Arquivo .txt com os dominios")
    tf = Path(target_file).expanduser()
    if not tf.is_file():
        sys.exit(f"[!] Arquivo nao encontrado: {tf}")

    targets = []
    for line in read_file_text(tf).splitlines():
        t = normalize_target(line)
        if t:
            targets.append(t)
    if not targets:
        sys.exit("[!] Nenhum alvo valido no arquivo.")

    print(f"[+] {len(targets)} alvo(s) carregado(s) de {tf}")

    size_choice = choose("Tamanho da wordlist generica", SIZE_WORDLISTS)
    lang_choice = choose("Linguagem / Stack (define extensoes e wordlist extra)", LANG_WORDLISTS,
                         show_path=False)

    size_name, size_path = size_choice
    lang_name, lang_path, lang_exts = lang_choice

    if not size_path.is_file():
        sys.exit(f"[!] Wordlist generica nao existe: {size_path}")

    # Combina wordlist generica + especifica (se existir)
    wordlists = [size_path]
    if lang_path and lang_path.is_file():
        wordlists.append(lang_path)
    elif lang_path:
        print(f"[!] Wordlist de linguagem nao encontrada ({lang_path}), seguindo so com a generica.")

    if len(wordlists) > 1:
        merged = Path(tempfile.gettempdir()) / f"gobuster_merged_{os.getpid()}.txt"
        seen = set()
        with merged.open("w", encoding="utf-8") as out:
            for w in wordlists:
                for ln in read_file_text(w).splitlines():
                    ln = ln.strip()
                    if ln and not ln.startswith("#") and ln not in seen:
                        seen.add(ln)
                        out.write(ln + "\n")
        wordlist = merged
        print(f"[+] Wordlist combinada: {wordlist} ({len(seen)} entradas)")
    else:
        wordlist = size_path
        print(f"[+] Wordlist: {wordlist}")

    print(f"[+] Stack: {lang_name} | extensoes: {lang_exts or '(nenhuma)'}")

    extra_args = args.extra.split() if args.extra else []

    exclude_length = args.exclude_length
    if exclude_length is None:
        r = ask("Tamanhos de resposta a ignorar (vazio = nenhum, ex: 323 ou 323,1024,0-50)", "")
        exclude_length = r or None
    if exclude_length:
        print(f"[+] Ignorando responses com length: {exclude_length}")

    confirm = ask("Comecar? (s/N)", "N").lower()
    if confirm != "s":
        print("Cancelado.")
        return

    for t in targets:
        run_gobuster(t, wordlist, lang_exts, args.status, exclude_length,
                     args.threads, args.timeout, extra_args)

    print("\n[+] Fim.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Encerrado.")
