import winrm

# Configura a sessão com o IP completo da máquina Touch e a porta correta do WinRM
session = winrm.Session('http://10.129.138', auth=('KioskUser', 'K!0sk2026#'))

print("[*] Tentando executar o comando no Windows...")

try:
    # Executa o comando whoami para testar
    result = session.run_cmd('whoami')
    
    # Exibe o resultado retornado pelo Windows
    print("[+] Resposta do Servidor:")
    print(result.std_out.decode('utf-8'))
except Exception as e:
    print(f"[-] Erro ao conectar: {e}")
