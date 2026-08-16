"""Small TLS reverse proxy for the iOS Tailscale Serve TLS workaround.

It accepts only explicitly listed Tailscale peer IPs. TLS is terminated with a
certificate obtained by ``tailscale cert``; HTTP is then proxied to the
loopback-only Core. It can listen behind a Tailscale raw-TCP Serve forwarder and
validate the original peer from PROXY protocol v1 before starting TLS.
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import socket
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
MAX_REQUEST_BYTES = 20 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_PROXY_LINE_BYTES = 108


def parse_proxy_v1_line(line: bytes) -> tuple[str, int]:
    """Return the validated source address from a PROXY protocol v1 header."""
    if len(line) > MAX_PROXY_LINE_BYTES or not line.endswith(b"\r\n"):
        raise ValueError("Invalid PROXY protocol header")
    try:
        fields = line[:-2].decode("ascii").split(" ")
    except UnicodeDecodeError as exc:
        raise ValueError("Invalid PROXY protocol header") from exc
    if len(fields) != 6 or fields[0] != "PROXY" or fields[1] not in {"TCP4", "TCP6"}:
        raise ValueError("Invalid PROXY protocol header")
    source = ipaddress.ip_address(fields[2])
    destination = ipaddress.ip_address(fields[3])
    expected_version = 4 if fields[1] == "TCP4" else 6
    if source.version != expected_version or destination.version != expected_version:
        raise ValueError("Invalid PROXY protocol address family")
    try:
        source_port = int(fields[4])
        destination_port = int(fields[5])
    except ValueError as exc:
        raise ValueError("Invalid PROXY protocol port") from exc
    if not 1 <= source_port <= 65535 or not 1 <= destination_port <= 65535:
        raise ValueError("Invalid PROXY protocol port")
    return str(source), source_port


def read_proxy_v1_line(connection: socket.socket) -> bytes:
    """Read one bounded CRLF-terminated PROXY protocol v1 header."""
    line = bytearray()
    while len(line) <= MAX_PROXY_LINE_BYTES:
        chunk = connection.recv(1)
        if not chunk:
            break
        line.extend(chunk)
        if line.endswith(b"\r\n"):
            return bytes(line)
    raise ValueError("Invalid PROXY protocol header")


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        upstream_host: str,
        upstream_port: int,
        allowed_clients: frozenset[str],
        tailscale_login: str,
        tls_context: ssl.SSLContext,
        proxy_protocol_v1: bool,
    ) -> None:
        super().__init__(server_address, handler_class)
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.allowed_clients = allowed_clients
        self.tailscale_login = tailscale_login
        self.tls_context = tls_context
        self.proxy_protocol_v1 = proxy_protocol_v1

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        connection, client_address = super().get_request()
        connection.settimeout(10)
        try:
            if self.proxy_protocol_v1:
                client_address = parse_proxy_v1_line(read_proxy_v1_line(connection))
            tls_connection = self.tls_context.wrap_socket(connection, server_side=True)
            tls_connection.settimeout(None)
            return tls_connection, client_address
        except (OSError, ValueError, ssl.SSLError):
            connection.close()
            raise


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "PersonalAgentTLSProxy"
    sys_version = ""

    @property
    def proxy_server(self) -> ProxyServer:
        assert isinstance(self.server, ProxyServer)
        return self.server

    def _send_text(self, status_code: int, message: str) -> None:
        payload = message.encode()
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _proxy(self) -> None:
        client_ip = str(ipaddress.ip_address(self.client_address[0]))
        if client_ip not in self.proxy_server.allowed_clients:
            self._send_text(403, "Tailscale peer is not allowed")
            return
        if not self.path.startswith("/") or urlsplit(self.path).netloc:
            self._send_text(400, "Invalid request target")
            return
        if self.headers.get("Upgrade", "").casefold() == "websocket":
            self._send_text(426, "WebSocket is not available on the iOS TLS fallback")
            return
        if "chunked" in self.headers.get("Transfer-Encoding", "").casefold():
            self._send_text(400, "Chunked request bodies are not supported")
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_text(400, "Invalid Content-Length")
            return
        if content_length < 0 or content_length > MAX_REQUEST_BYTES:
            self._send_text(413, "Request body is too large")
            return
        body = self.rfile.read(content_length) if content_length else None
        headers = {
            name: value
            for name, value in self.headers.items()
            if name.casefold() not in HOP_BY_HOP_HEADERS
            and name.casefold()
            not in {
                "content-length",
                "tailscale-user-login",
                "x-forwarded-for",
                "x-forwarded-proto",
                "x-personal-agent-remote-proxy",
            }
        }
        headers["Host"] = self.headers.get("Host", "")
        headers["Tailscale-User-Login"] = self.proxy_server.tailscale_login
        headers["X-Personal-Agent-Remote-Proxy"] = "tailscale-direct-tls-v1"
        headers["X-Forwarded-For"] = client_ip
        headers["X-Forwarded-Proto"] = "https"
        if body is not None:
            headers["Content-Length"] = str(len(body))

        connection = http.client.HTTPConnection(
            self.proxy_server.upstream_host,
            self.proxy_server.upstream_port,
            timeout=120,
        )
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            upstream = connection.getresponse()
            payload = upstream.read(MAX_RESPONSE_BYTES + 1)
            if len(payload) > MAX_RESPONSE_BYTES:
                self._send_text(502, "Upstream response is too large")
                return
            self.send_response(upstream.status, upstream.reason)
            for name, value in upstream.getheaders():
                if name.casefold() not in HOP_BY_HOP_HEADERS | {"content-length"}:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
        except (ConnectionError, TimeoutError, http.client.HTTPException):
            self._send_text(502, "Personal Agent Core is unavailable")
        finally:
            connection.close()

    do_DELETE = _proxy
    do_GET = _proxy
    do_HEAD = _proxy
    do_PATCH = _proxy
    do_POST = _proxy
    do_PUT = _proxy

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", required=True)
    parser.add_argument("--listen-port", type=int, default=9443)
    parser.add_argument("--upstream-host", default="127.0.0.1")
    parser.add_argument("--upstream-port", type=int, default=8789)
    parser.add_argument("--cert-file", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--allowed-client", action="append", required=True)
    parser.add_argument("--tailscale-login", required=True)
    parser.add_argument("--proxy-protocol-v1", action="store_true")
    args = parser.parse_args()

    listen_host = str(ipaddress.ip_address(args.listen_host))
    tailscale_ipv4 = ipaddress.ip_network("100.64.0.0/10")
    listen_address = ipaddress.ip_address(listen_host)
    if not (listen_address.is_private or listen_address in tailscale_ipv4):
        raise SystemExit("The listener must use a private/Tailscale address")
    allowed_clients = frozenset(
        str(ipaddress.ip_address(value)) for value in args.allowed_client
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert_file, args.key_file)

    server = ProxyServer(
        (listen_host, args.listen_port),
        ProxyHandler,
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        allowed_clients=allowed_clients,
        tailscale_login=args.tailscale_login.casefold(),
        tls_context=context,
        proxy_protocol_v1=args.proxy_protocol_v1,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
