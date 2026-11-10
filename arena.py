#!/usr/bin/env python3
"""Small, intentionally vulnerable, offline-only teaching arena. No external dependencies."""
import argparse
import codecs
from contextlib import closing
import hmac
import os
import time
import json
import secrets
import signal
import sys
import socket
import socketserver
import sqlite3
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

NAMES = ("discovery", "sqli", "idor", "dns", "encoding")
POINTS = dict(zip(NAMES, (50, 150, 100, 100, 50)))
FLAGS = {}
ARENA_IP = "192.168.77.10"


def make_flags():
    return {name: "flag{" + name + "_" + secrets.token_hex(12) + "}" for name in NAMES}


class BoundedThreads(socketserver.ThreadingMixIn):
    daemon_threads = True
    block_on_close = False
    capacity = 4

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(self.capacity)
        super().__init__(*args, **kwargs)

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (OSError, EOFError)):
            return  # Closed/timed-out peers are normal; avoid traceback/log storms.
        super().handle_error(request, client_address)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        timer = None
        if isinstance(request, socket.socket):
            def expire():
                try:
                    request.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            timer = threading.Timer(10, expire)
            timer.daemon = True
            timer.start()  # Absolute connection deadline, even for trickled input.
        try:
            super().process_request_thread(request, client_address)
        finally:
            if timer:
                timer.cancel()
            self.slots.release()


class HTTPArena(BoundedThreads, HTTPServer):
    allow_reuse_address = True
    capacity = 16


class TCPArena(BoundedThreads, socketserver.TCPServer):
    allow_reuse_address = True
    capacity = 4


class UDPArena(BoundedThreads, socketserver.UDPServer):
    allow_reuse_address = True
    capacity = 8


HOME = b'''<!doctype html><meta charset="utf-8"><title>Offline CTF</title>
<style>body{font:18px system-ui;max-width:850px;margin:3em auto;padding:1em;background:#101826;color:#e3edf9}a{color:#89cbff}input{padding:.5em}</style>
<h1>Offline CTF: five flags, 450 points</h1>
<p>Scope: only this Raspberry Pi (192.168.77.10). The router, other players, and all other networks are OUT OF SCOPE.</p>
<ol><li>Discovery (50): what does this site ask robots not to index?</li>
<li>SQL injection (150): <a href="/login">log in</a> without knowing the password.</li>
<li>IDOR (100): <a href="/api/record?id=1">your record</a> is ID 1. Find the administrator's record; the answer to everything may help.</li>
<li>DNS (100): the authoritative server on this Pi has a TXT secret under vault.ctf.lan. Query it directly.</li>
<li>Encoding (50): inspect the TCP service on port 31337. Encoding is not encryption.</li></ol>
<p>Submit with POST /submit: form field flag, or JSON {"flag":"..."}. Validation is stateless; record your own score.</p>
<form method="post" action="/submit"><input name="flag" placeholder="flag{...}" size="48"><button>Check flag</button></form>
<p>Use only tools and devices you own or have permission to use. No denial-of-service tests.</p>'''
LOGIN = b'''<!doctype html><title>CTF login</title><h1>Login</h1>
<form method="post" action="/login"><input name="username" placeholder="username"><input name="password" type="password" placeholder="password"><button>Login</button></form>'''


class Web(BaseHTTPRequestHandler):
    server_version = "OfflineCTF/1.0"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_args):
        pass  # Do not retain client addresses or submitted flags.

    def send_body(self, status, body, kind="application/json"):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def route(self):
        try:
            return urlsplit(self.path)
        except ValueError:
            self.send_body(400, {"error": "invalid URL"})
            return None

    def do_GET(self):
        if len(self.path) > 8192:
            return self.send_body(414, {"error": "URI too long"})
        path = self.route()
        if path is None:
            return
        if path.path == "/":
            self.send_body(200, HOME, "text/html; charset=utf-8")
        elif path.path == "/health":
            self.send_body(200, {"status": "ok", "challenges": 5})
        elif path.path == "/login":
            self.send_body(200, LOGIN, "text/html; charset=utf-8")
        elif path.path == "/robots.txt":
            self.send_body(200, b"User-agent: *\nDisallow: /maintenance/notes.txt\n", "text/plain")
        elif path.path == "/maintenance/notes.txt":
            self.send_body(200, (FLAGS["discovery"] + "\n").encode(), "text/plain")
        elif path.path == "/api/record":
            try:
                record_id = int(parse_qs(path.query).get("id", ["1"])[0])
            except (ValueError, IndexError):
                return self.send_body(400, {"error": "integer id required"})
            # INTENTIONAL IDOR: accepts another record ID with no ownership check.
            if record_id == 1:
                self.send_body(200, {"id": 1, "owner": "player", "note": "Try a different id"})
            elif record_id == 42:
                self.send_body(200, {"id": 42, "owner": "admin", "flag": FLAGS["idor"]})
            else:
                self.send_body(404, {"error": "record not found"})
        else:
            self.send_body(404, {"error": "not found"})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if not 0 <= length <= 4096:
                return self.send_body(413, {"error": "body must be at most 4096 bytes"})
            if self.headers.get("Transfer-Encoding"):
                return self.send_body(400, {"error": "chunked bodies unsupported"})
            raw = self.rfile.read(length).decode("utf-8")
            if self.headers.get("Content-Type", "").split(";", 1)[0] == "application/json":
                data = json.loads(raw)
            else:
                data = {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}
            if not isinstance(data, dict) or any(not isinstance(v, str) for v in data.values()):
                raise ValueError("string fields required")
        except (ValueError, UnicodeError, socket.timeout):
            return self.send_body(400, {"error": "invalid body"})
        route = self.route()
        if route is None:
            return
        path = route.path
        if path == "/submit":
            try:
                submitted = data.get("flag", "").encode()
            except UnicodeError:
                return self.send_body(400, {"error": "invalid Unicode"})
            for name, flag in FLAGS.items():
                if hmac.compare_digest(submitted, flag.encode()):
                    return self.send_body(200, {"correct": True, "challenge": name, "points": POINTS[name]})
            self.send_body(400, {"correct": False})
        elif path == "/login":
            # INTENTIONAL SQLi, confined to a disposable in-memory SQLite database.
            username = data.get("username", "")
            password = data.get("password", "")
            with closing(sqlite3.connect(":memory:")) as db:
                db.execute("CREATE TABLE users (username TEXT, password TEXT)")
                db.execute("INSERT INTO users VALUES (?, ?)", ("admin", secrets.token_hex(24)))
                db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 65536)
                db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 8192)
                db.setlimit(sqlite3.SQLITE_LIMIT_VDBE_OP, 10000)
                denied = {sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE,
                          sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_PRAGMA}
                db.set_authorizer(lambda action, *_: sqlite3.SQLITE_DENY if action in denied else sqlite3.SQLITE_OK)
                deadline = time.monotonic() + 0.05
                db.set_progress_handler(lambda: int(time.monotonic() > deadline), 100)
                query = "SELECT username FROM users WHERE username='%s' AND password='%s'" % (username, password)
                try:
                    result = db.execute(query).fetchone()
                except (sqlite3.Error, UnicodeError, MemoryError):
                    return self.send_body(400, {"error": "SQL syntax or safety limit error"})
            self.send_body(200 if result else 403,
                           {"flag": FLAGS["sqli"]} if result else {"error": "incorrect login"})
        else:
            self.send_body(404, {"error": "not found"})


def dns_reply(packet):
    """Authoritative, non-recursive DNS. One uncompressed question, bounded packet size."""
    if not 12 <= len(packet) <= 4096:
        return None
    ident, bits, qd, _an, _ns, _ar = struct.unpack("!6H", packet[:12])
    if bits & 0xF800 or qd != 1:
        return None  # Not a standard query, or QR set.
    pos, labels, total = 12, [], 0
    while True:
        if pos >= len(packet):
            return None
        size = packet[pos]
        pos += 1
        if size == 0:
            break
        if size > 63 or pos + size > len(packet):
            return None  # Compression pointers in a request are intentionally unsupported.
        total += size + 1
        if total > 253:
            return None
        try:
            labels.append(packet[pos:pos + size].decode("ascii").lower())
        except UnicodeError:
            return None
        pos += size
    if pos + 4 > len(packet):
        return None
    qtype, qclass = struct.unpack("!HH", packet[pos:pos + 4])
    question = packet[12:pos + 4]
    name = ".".join(labels)
    answer, rcode = b"", 0
    known = name in ("ctf.lan", "arena.ctf.lan", "vault.ctf.lan")
    if qclass != 1:
        rcode = 5
    elif not known:
        rcode = 3
    elif name in ("ctf.lan", "arena.ctf.lan") and qtype == 1:
        rdata = socket.inet_aton(ARENA_IP)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, len(rdata)) + rdata
    elif name == "vault.ctf.lan" and qtype == 16:
        text = FLAGS["dns"].encode()
        rdata = bytes([len(text)]) + text
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 30, len(rdata)) + rdata
    response_bits = 0x8400 | (bits & 0x0100) | rcode  # QR, AA; echo RD, never RA.
    return struct.pack("!6H", ident, response_bits, 1, int(bool(answer)), 0, 0) + question + answer


class DNSUDP(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        response = dns_reply(packet)
        if response is not None:
            sock.sendto(response, self.client_address)


def read_exact(sock, count):
    parts = bytearray()
    while len(parts) < count:
        part = sock.recv(count - len(parts))
        if not part:
            raise EOFError
        parts.extend(part)
    return bytes(parts)


class DNSTCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            size = struct.unpack("!H", read_exact(self.request, 2))[0]
            if not 12 <= size <= 4096:
                return
            response = dns_reply(read_exact(self.request, size))
            if response:
                self.request.sendall(struct.pack("!H", len(response)) + response)
        except (EOFError, OSError):
            return


class Banner(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        text = "Offline CTF: ROT13 is not encryption.\n" + codecs.encode(FLAGS["encoding"], "rot_13") + "\n"
        self.request.sendall(text.encode())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--flags", type=Path, required=True)
    parser.add_argument("--bind", default="192.168.77.10")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--dns-port", type=int, default=53)
    parser.add_argument("--tcp-port", type=int, default=31337)
    parser.add_argument("--generate", action="store_true")
    args = parser.parse_args()
    if args.generate:
        if args.flags.exists():
            parser.error("flags file already exists; delete explicitly to rotate")
        args.flags.write_text(json.dumps(make_flags(), indent=2) + "\n")
        args.flags.chmod(0o640)
        return
    global FLAGS, ARENA_IP
    FLAGS = json.loads(args.flags.read_text())
    if set(FLAGS) != set(NAMES) or any(not isinstance(v, str) or len(v.encode()) > 200 for v in FLAGS.values()):
        parser.error("invalid flags file")
    ARENA_IP = args.bind
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    servers = []
    try:
        for server_type, port, handler in ((HTTPArena, args.http_port, Web),
                                          (UDPArena, args.dns_port, DNSUDP),
                                          (TCPArena, args.dns_port, DNSTCP),
                                          (TCPArena, args.tcp_port, Banner)):
            server = server_type((args.bind, port), handler)
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        notify = os.environ.get("NOTIFY_SOCKET")
        if notify:
            if notify.startswith("@"):
                notify = "\0" + notify[1:]
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
                notifier.sendto(b"READY=1", notify)
        print("Offline CTF ready", flush=True)
        stop.wait()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
