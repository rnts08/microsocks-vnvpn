#!/usr/bin/env python3
"""Integration test: end-to-end SOCKS5 auth + accounting under concurrent load."""

from __future__ import annotations

import concurrent.futures
import os
import socket
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

USERNAME = "loaduser"
PASSWORD = "loadpass"
REQUESTS = 40
CONCURRENCY = 10
SOCKS_CONNECT_TIMEOUT = 5.0


class PayloadHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # suppress noisy access logs
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        query = parse_qs(urlparse(self.path).query)
        size = int(query.get("size", ["1024"])[0])
        if size < 0:
            size = 0
        payload = b"x" * size
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining:
        part = sock.recv(remaining)
        if not part:
            raise RuntimeError("unexpected EOF")
        chunks.append(part)
        remaining -= len(part)
    return b"".join(chunks)


def socks5_connect(host: str, port: int, username: str, password: str) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=SOCKS_CONNECT_TIMEOUT)

    # method negotiation: username/password only
    sock.sendall(b"\x05\x01\x02")
    method_reply = recv_exact(sock, 2)
    if method_reply != b"\x05\x02":
        raise RuntimeError(f"unexpected method negotiation reply: {method_reply!r}")

    user_b = username.encode("utf-8")
    pass_b = password.encode("utf-8")
    if len(user_b) > 255 or len(pass_b) > 255:
        raise RuntimeError("username/password too long for RFC1929")
    auth_req = b"\x01" + bytes([len(user_b)]) + user_b + bytes([len(pass_b)]) + pass_b
    sock.sendall(auth_req)
    auth_reply = recv_exact(sock, 2)
    if auth_reply != b"\x01\x00":
        raise RuntimeError(f"authentication failed: {auth_reply!r}")

    # CONNECT request for IPv4 127.0.0.1
    host_bytes = socket.inet_aton(host)
    req = b"\x05\x01\x00\x01" + host_bytes + struct.pack("!H", port)
    sock.sendall(req)
    rep_head = recv_exact(sock, 4)
    if rep_head[1] != 0x00:
        raise RuntimeError(f"connect failed with reply code {rep_head[1]}")

    atyp = rep_head[3]
    if atyp == 0x01:  # IPv4
        recv_exact(sock, 4)
    elif atyp == 0x03:  # domain
        ln = recv_exact(sock, 1)[0]
        recv_exact(sock, ln)
    elif atyp == 0x04:  # IPv6
        recv_exact(sock, 16)
    else:
        raise RuntimeError(f"unknown ATYP in connect reply: {atyp}")
    recv_exact(sock, 2)  # bind port

    return sock


def tunnel_http_once(body_size: int, response_size: int) -> tuple[int, int]:
    body = os.urandom(body_size)
    request = (
        b"POST /echo HTTP/1.1\r\n"
        + f"Host: 127.0.0.1:{HTTP_PORT}\r\n".encode("ascii")
        + b"Content-Type: application/octet-stream\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n"
        + b"\r\n"
        + body
    )

    sock = socks5_connect("127.0.0.1", HTTP_PORT, USERNAME, PASSWORD)
    try:
        sock.sendall(request)
        raw_response = b""
        while True:
            part = sock.recv(4096)
            if not part:
                break
            raw_response += part
    finally:
        sock.close()

    _, resp_body = raw_response.split(b"\r\n\r\n", 1)
    if resp_body != body:
        raise RuntimeError("echo payload mismatch")

    # second independent request to generate additional accounting
    get_req = (
        f"GET /?size={response_size} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{HTTP_PORT}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    sock2 = socks5_connect("127.0.0.1", HTTP_PORT, USERNAME, PASSWORD)
    try:
        sock2.sendall(get_req)
        raw_get = b""
        while True:
            part = sock2.recv(4096)
            if not part:
                break
            raw_get += part
    finally:
        sock2.close()
    _, get_body = raw_get.split(b"\r\n\r\n", 1)
    if len(get_body) != response_size:
        raise RuntimeError(f"GET payload length mismatch: expected {response_size}, got {len(get_body)}")

    uploaded = len(request) + len(get_req)
    downloaded = len(raw_response) + len(raw_get)
    return uploaded, downloaded


def wait_for_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port {port} did not become ready")


def verify_auth_failure() -> None:
    sock = socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=SOCKS_CONNECT_TIMEOUT)
    try:
        sock.sendall(b"\x05\x01\x02")
        if recv_exact(sock, 2) != b"\x05\x02":
            raise RuntimeError("server did not accept username/password auth method")
        bad = b"\x01\x08bad-user\x08bad-pass"
        sock.sendall(bad)
        reply = recv_exact(sock, 2)
        if reply[1] == 0x00:
            raise RuntimeError("unexpected successful auth with bad credentials")
    finally:
        sock.close()


REPO_ROOT = Path(__file__).resolve().parents[1]
MSADMIN = REPO_ROOT / "msadmin"
MICROSOCKS = REPO_ROOT / "microsocks"
if not MSADMIN.exists() or not MICROSOCKS.exists():
    raise SystemExit("Build binaries first: run `make`.")

HTTP_PORT = find_free_port()
SOCKS_PORT = find_free_port()

http_server = ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), PayloadHandler)
http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
http_thread.start()

microsocks_proc: subprocess.Popen[str] | None = None

tmpdir = tempfile.TemporaryDirectory(prefix="msocks-e2e-")
try:
    db_path = Path(tmpdir.name) / "microsocks.db"
    subprocess.run(
        [str(MSADMIN), "-d", str(db_path), "add", USERNAME, PASSWORD, "0"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    microsocks_proc = subprocess.Popen(
        [
            str(MICROSOCKS),
            "-i",
            "127.0.0.1",
            "-p",
            str(SOCKS_PORT),
            "-d",
            str(db_path),
            "-q",
        ],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    wait_for_port(SOCKS_PORT)

    verify_auth_failure()

    totals = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [
            pool.submit(tunnel_http_once, 2048 + (i % 512), 3072 + (i % 1024))
            for i in range(REQUESTS)
        ]
        for fut in concurrent.futures.as_completed(futures):
            totals.append(fut.result())

    expected_connections = REQUESTS * 2

    con = sqlite3.connect(db_path)
    try:
        row = con.execute(
            "SELECT id, m_bytes_sent, m_bytes_received, total_bytes_sent, total_bytes_received "
            "FROM accounts WHERE username = ?",
            (USERNAME,),
        ).fetchone()
        if row is None:
            raise RuntimeError("test user not found in DB after load")
        account_id, m_sent, m_recv, t_sent, t_recv = row

        c_row = con.execute(
            "SELECT COUNT(*), COALESCE(SUM(bytes_sent), 0), COALESCE(SUM(bytes_received), 0) "
            "FROM connections WHERE account_id = ? AND status = 'success'",
            (account_id,),
        ).fetchone()
        assert c_row is not None
        conn_count, conn_sent_sum, conn_recv_sum = c_row
    finally:
        con.close()

    if conn_count != expected_connections:
        raise RuntimeError(f"expected {expected_connections} successful connections, got {conn_count}")

    if not (m_sent == t_sent == conn_sent_sum):
        raise RuntimeError(
            f"sent accounting mismatch: monthly={m_sent}, total={t_sent}, connections={conn_sent_sum}"
        )
    if not (m_recv == t_recv == conn_recv_sum):
        raise RuntimeError(
            f"recv accounting mismatch: monthly={m_recv}, total={t_recv}, connections={conn_recv_sum}"
        )

    min_uploaded = sum(upload for upload, _ in totals)
    min_downloaded = sum(download for _, download in totals)
    if conn_sent_sum < min_uploaded:
        raise RuntimeError(f"sent sum too small: got {conn_sent_sum}, expected at least {min_uploaded}")
    if conn_recv_sum < min_downloaded:
        raise RuntimeError(f"recv sum too small: got {conn_recv_sum}, expected at least {min_downloaded}")

    print(
        "PASS: concurrent SOCKS5 auth + accounting verified "
        f"({REQUESTS} tasks, {expected_connections} successful tunnels)"
    )
finally:
    if microsocks_proc is not None:
        microsocks_proc.terminate()
        try:
            microsocks_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            microsocks_proc.kill()
            microsocks_proc.wait(timeout=5)
    http_server.shutdown()
    http_server.server_close()
    tmpdir.cleanup()
