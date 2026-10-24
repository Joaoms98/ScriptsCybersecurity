#!/usr/bin/env python3
"""
Hydra scan runner - roda hydra em uma lista de alvos lidos de um arquivo .txt,
com escolha interativa de servico, wordlist de usuario e de senha a partir do SecLists.
"""
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

# SecLists: usa a variavel de ambiente SECLISTS se definida, senao assume
# a copia dentro do proprio projeto (WordLists/SecLists ao lado do script).
SECLISTS_BASE = Path(
    os.environ.get("SECLISTS")
    or (Path(__file__).resolve().parent / "WordLists" / "SecLists")
)
PASS_DIR     = SECLISTS_BASE / "Passwords"
COMMON_DIR   = PASS_DIR / "Common-Credentials"
LEAKED_DIR   = PASS_DIR / "Leaked-Databases"
DEFAULT_DIR  = PASS_DIR / "Default-Credentials"
USER_DIR     = SECLISTS_BASE / "Usernames"
USER_NAMES   = USER_DIR / "Names"

# ---------------------------------------------------------------------------
# Servicos suportados pelo hydra (os mais usados)
# Formato: (nome, modulo_hydra, porta_padrao, exige_path_bool)
# ---------------------------------------------------------------------------
SERVICES = {
    "1":  ("SSH",            "ssh",         22,    False),
    "2":  ("FTP",            "ftp",         21,    False),
    "3":  ("Telnet",         "telnet",      23,    False),
    "4":  ("MySQL",          "mysql",       3306,  False),
    "5":  ("PostgreSQL",     "postgres",    5432,  False),
    "6":  ("MSSQL",          "mssql",       1433,  False),
    "7":  ("Oracle",         "oracle-listener", 1521, False),
    "8":  ("RDP",            "rdp",         3389,  False),
    "9":  ("SMB",            "smb",         445,   False),
    "10": ("SMTP",           "smtp",        25,    False),
    "11": ("POP3",           "pop3",        110,   False),
    "12": ("IMAP",           "imap",        143,   False),
    "13": ("VNC",            "vnc",         5900,  False),
    "14": ("LDAP",           "ldap2",       389,   False),
    "15": ("HTTP Basic Auth (GET)",  "http-get",   80,  True),
    "16": ("HTTPS Basic Auth (GET)", "https-get",  443, True),
    "17": ("HTTP Form POST",         "http-post-form", 80,  True),
    "18": ("HTTPS Form POST",        "https-post-form", 443, True),
    "19": ("HTTP Form GET",          "http-get-form",  80,  True),
    "20": ("MongoDB",        "mongodb",     27017, False),
    "21": ("Redis",          "redis",       6379,  False),
    "22": ("SNMP",           "snmp",        161,   False),
    "23": ("CISCO Enable",   "cisco-enable", 23,   False),
}

# ---------------------------------------------------------------------------
# Wordlists de SENHA
# ---------------------------------------------------------------------------
PASS_WORDLISTS = {
    "1":  ("Top 200 - mais usadas 2025",        COMMON_DIR / "2025-199_most_used_passwords.txt"),
    "2":  ("Top 500 piores",                    COMMON_DIR / "500-worst-passwords.txt"),
    "3":  ("Top 1k Pwdb",                       COMMON_DIR / "Pwdb_top-1000.txt"),
    "4":  ("Top 10k Pwdb",                      COMMON_DIR / "Pwdb_top-10000.txt"),
    "5":  ("Top 100k Pwdb",                     COMMON_DIR / "Pwdb_top-100000.txt"),
    "6":  ("10k mais comuns",                   COMMON_DIR / "10k-most-common.txt"),
    "7":  ("100k NCSC",                         COMMON_DIR / "100k-most-used-passwords-NCSC.txt"),
    "8":  ("rockyou (completa)",                LEAKED_DIR / "rockyou.txt"),
    "9":  ("rockyou-10 (10%)",                  LEAKED_DIR / "rockyou-10.txt"),
    "10": ("rockyou-25 (25%)",                  LEAKED_DIR / "rockyou-25.txt"),
    "11": ("Darkweb 2017 top-10000",            COMMON_DIR / "darkweb2017_top-10000.txt"),
    "12": ("Default passwords (geral)",         DEFAULT_DIR / "default-passwords.txt"),
    "13": ("SSH default passwords",             DEFAULT_DIR / "ssh-betterdefaultpasslist.txt"),
    "14": ("FTP default passwords",             DEFAULT_DIR / "ftp-betterdefaultpasslist.txt"),
    "15": ("MySQL default passwords",           DEFAULT_DIR / "mysql-betterdefaultpasslist.txt"),
    "16": ("MSSQL default passwords",           DEFAULT_DIR / "mssql-betterdefaultpasslist.txt"),
    "17": ("PostgreSQL default passwords",      DEFAULT_DIR / "postgres-betterdefaultpasslist.txt"),
    "18": ("Oracle default passwords",          DEFAULT_DIR / "oracle-betterdefaultpasslist.txt"),
    "19": ("Telnet default passwords",          DEFAULT_DIR / "telnet-betterdefaultpasslist.txt"),
    "20": ("Corporate passwords",               PASS_DIR / "corporate_passwords.txt"),
    "21": ("Senha unica (digito agora)",        None),
    "22": ("Arquivo custom (digito o path)",    None),
}

# ---------------------------------------------------------------------------
# Wordlists de USUARIO
# ---------------------------------------------------------------------------
USER_WORDLISTS = {
    "1":  ("Top usernames shortlist",           USER_DIR / "top-usernames-shortlist.txt"),
    "2":  ("CIRT default usernames",            USER_DIR / "cirt-default-usernames.txt"),
    "3":  ("Common admin base64",               USER_DIR / "CommonAdminBase64.txt"),
    "4":  ("MSSQL usernames",                   USER_DIR / "mssql-usernames-nansh0u-guardicore.txt"),
    "5":  ("SAP default usernames",             USER_DIR / "sap-default-usernames.txt"),
    "6":  ("xato 10M (dedup)",                  USER_DIR / "xato-net-10-million-usernames.txt"),
    "7":  ("Nomes BR (top100k)",                USER_NAMES / "names-brazil-top100000.txt"),
    "8":  ("Nomes USA familia (top1k)",         USER_NAMES / "familynames-usa-top1000.txt"),
    "9":  ("Nomes USA masc (top1k)",            USER_NAMES / "malenames-usa-top1000.txt"),
    "10": ("Nomes USA fem (top1k)",             USER_NAMES / "femalenames-usa-top1000.txt"),
    "11": ("Usuario unico (digito agora)",      None),
    "12": ("Arquivo custom (digito o path)",    None),
    "13": ("Nenhum - testar so senhas (-l '')", "SKIP"),
}


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


def choose(title, mapping):
    print(f"\n== {title} ==")
    for k, v in mapping.items():
        name = v[0]
        extra = ""
        if len(v) > 1 and isinstance(v[1], Path):
            exists = "" if v[1].is_file() else "  [FALTA]"
            extra = f"  -> {v[1]}{exists}"
        print(f"  {k}) {name}{extra}")
    while True:
        c = input("Escolha: ").strip()
        if c in mapping:
            return mapping[c]
        print("Opcao invalida.")


def pick_wordlist(choice, kind):
    """
    Resolve a escolha em:
      ("single", "valor")  -> login/senha unico
      ("file",   Path)     -> wordlist de arquivo
      ("skip",   None)     -> nao passar -l/-L (so pra usuario)
    """
    name = choice[0]
    path = choice[1] if len(choice) > 1 else None

    if path == "SKIP":
        return ("skip", None)

    if path is None:
        if "unica" in name.lower() or "unico" in name.lower():
            v = ask(f"Digite o {kind}")
            if not v:
                sys.exit("[!] Vazio.")
            return ("single", v)
        if "custom" in name.lower():
            v = ask(f"Caminho do arquivo de {kind}")
            p = Path(v).expanduser()
            if not p.is_file():
                sys.exit(f"[!] Arquivo nao existe: {p}")
            return ("file", p)

    if not isinstance(path, Path) or not path.is_file():
        sys.exit(f"[!] Wordlist nao encontrada: {path}")
    return ("file", path)


def normalize_target(line):
    t = line.strip()
    if not t or t.startswith("#"):
        return None
    return t


def build_cmd(target, port, module, user_sel, pass_sel, threads, extra_args,
              service_needs_path, http_path):
    cmd = ["hydra"]

    if user_sel[0] == "single":
        cmd += ["-l", user_sel[1]]
    elif user_sel[0] == "file":
        cmd += ["-L", str(user_sel[1])]

    if pass_sel[0] == "single":
        cmd += ["-p", pass_sel[1]]
    elif pass_sel[0] == "file":
        cmd += ["-P", str(pass_sel[1])]

    cmd += ["-t", str(threads), "-I", "-V", "-f"]

    if port:
        cmd += ["-s", str(port)]

    cmd += extra_args

    service_arg = f"{module}://{target}"
    if service_needs_path:
        service_arg += http_path
    cmd += [service_arg]
    return cmd


def main():
    p = argparse.ArgumentParser(description="Roda hydra em uma lista de alvos.")
    p.add_argument("file", nargs="?", help="arquivo .txt com um host/IP por linha")
    p.add_argument("--threads", type=int, default=16, help="tasks por alvo (-t)")
    p.add_argument("--extra", default="",
                   help="argumentos extras para hydra entre aspas, ex: --extra='-e nsr'")
    args = p.parse_args()

    if not shutil.which("hydra"):
        sys.exit("[!] hydra nao esta no PATH. Instale com: sudo apt install hydra")

    if not SECLISTS_BASE.exists():
        sys.exit(f"[!] SecLists nao encontrado em {SECLISTS_BASE}")

    target_file = args.file or ask("Arquivo .txt com os alvos")
    tf = Path(target_file).expanduser()
    if not tf.is_file():
        sys.exit(f"[!] Arquivo nao encontrado: {tf}")

    targets = [t for t in (normalize_target(l) for l in
               read_file_text(tf).splitlines()) if t]
    if not targets:
        sys.exit("[!] Nenhum alvo valido no arquivo.")

    print(f"[+] {len(targets)} alvo(s) carregado(s) de {tf}")

    svc = choose("Servico/protocolo", SERVICES)
    svc_name, module, default_port, needs_path = svc

    port_in = ask(f"Porta (vazio = padrao {default_port})", "")
    port = int(port_in) if port_in else default_port

    http_path = ""
    if needs_path:
        if "form" in module:
            print("\nFormato Hydra para http-post-form / http-get-form:")
            print('  "/caminho:campo_user=^USER^&campo_pass=^PASS^:F=mensagem de erro"')
            print('  ex: "/login.php:user=^USER^&pass=^PASS^:F=invalid"')
            http_path = ask("String do form")
        else:
            http_path = ask("Path do recurso protegido (ex: /admin)", "/")
        if not http_path.startswith("/"):
            http_path = "/" + http_path

    user_choice = choose("Wordlist de USUARIO", USER_WORDLISTS)
    user_sel    = pick_wordlist(user_choice, "usuario")

    pass_choice = choose("Wordlist de SENHA", PASS_WORDLISTS)
    pass_sel    = pick_wordlist(pass_choice, "senha")

    if user_sel[0] == "skip" and pass_sel[0] not in ("single", "file"):
        sys.exit("[!] Nenhum usuario e nenhuma senha? Nao da.")

    extra_args = args.extra.split() if args.extra else []

    print("\n== Resumo ==")
    print(f"  Alvos:   {len(targets)}")
    print(f"  Servico: {svc_name} ({module}) porta {port}")
    print(f"  User:    {user_sel}")
    print(f"  Pass:    {pass_sel}")
    print(f"  Threads: {args.threads}")
    if http_path:
        print(f"  Path:    {http_path}")

    confirm = ask("\nComecar? (s/N)", "N").lower()
    if confirm != "s":
        print("Cancelado.")
        return

    for t in targets:
        cmd = build_cmd(t, port, module, user_sel, pass_sel,
                        args.threads, extra_args, needs_path, http_path)
        print(f"\n[+] {t}")
        print(f"    -> {' '.join(cmd)}")
        try:
            subprocess.run(cmd, check=False)
        except KeyboardInterrupt:
            print("\n[!] Interrompido. Pulando para o proximo alvo.")

    print("\n[+] Fim.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Encerrado.")
