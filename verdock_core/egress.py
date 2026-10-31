"""Egress gateway: the one way out of a network isolated environment.

Agents run on a network with no route to the internet. This gateway is the
only process attached to both sides. It is an HTTP CONNECT proxy that opens
a TLS tunnel only to hosts on the policy allowlist, on port 443, and writes a
signed receipt for every request it sees, allowed or blocked. TLS stays end
to end between the agent and the provider, so the gateway sees host names
and byte counts, never request bodies, credentials or responses.

A refusal happens before any byte reaches the provider. Clients can therefore
tell "nothing was sent" (the gateway answered 403 or 502 to CONNECT) apart
from "the request may have taken effect" (the tunnel broke after it opened).

Receipt actions::

    verdock.egress.allowed   tunnel opened; params: host, port, sent, received
    verdock.egress.blocked   host or port not on the allowlist; params: host, port
    verdock.egress.offline   allowed host, but the upstream could not be reached

Standard library only. Start it with::

    python -m verdock_core egress --policy policy.yaml --listen 0.0.0.0:8080 \\
        --receipts egress.ndjson --seed egress.seed
"""

import re
import select
import socket
import socketserver
import threading

_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
_MAX_HEADER = 8192


def allowed_hosts(policy):
    """The allowlist from a validated policy, or an empty tuple (nothing leaves)."""
    return tuple(policy.get("egress", {}).get("allow_hosts", ()))


def parse_connect(head):
    """Return (host, port) from a CONNECT request head, or None if it is not one."""
    try:
        line = head.split(b"\r\n", 1)[0].decode("ascii")
    except UnicodeDecodeError:
        return None
    parts = line.split(" ")
    if len(parts) != 3 or parts[0] != "CONNECT" or not parts[2].startswith("HTTP/1."):
        return None
    host, _, port = parts[1].rpartition(":")
    host = host.lower()
    if (not _HOST.fullmatch(host) or host.rsplit(".", 1)[-1].isdigit()  # names only, never raw addresses
            or not port.isdigit() or not 0 < int(port) < 65536):
        return None
    return host, int(port)


class EgressGateway(socketserver.ThreadingTCPServer):
    """CONNECT only, allowlisted hosts only, port 443 only, every request receipted."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, allow_hosts, receipts, connect=None, timeout=15):
        self.allow = frozenset(h.lower() for h in allow_hosts)
        self.receipts, self.timeout = receipts, timeout
        self.connect = connect or (lambda host, port: socket.create_connection((host, port), timeout=timeout))
        self._writer = threading.Lock()
        self._count = 0
        super().__init__(address, _Handler)

    def receipt(self, action, params, success):
        with self._writer:  # one writer per chain
            self._count += 1
            return self.receipts.append("egress:%d" % self._count, action, params, success,
                                        actor={"agent": "verdock-egress", "user": "gateway"})


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        server, client = self.server, self.request
        client.settimeout(server.timeout)
        head = b""
        try:
            while b"\r\n\r\n" not in head and len(head) <= _MAX_HEADER:
                chunk = client.recv(1024)
                if not chunk:
                    return
                head += chunk
        except OSError:
            return
        target = parse_connect(head)
        if target is None:
            server.receipt("verdock.egress.blocked", {"host": "", "port": 0, "reason": "not a CONNECT request"}, False)
            client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        host, port = target
        if host not in server.allow or port != 443:
            server.receipt("verdock.egress.blocked", {"host": host, "port": port, "reason": "not on the allowlist"}, False)
            client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        try:
            upstream = server.connect(host, port)
        except OSError:
            server.receipt("verdock.egress.offline", {"host": host, "port": port, "reason": "upstream unreachable"}, False)
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        sent = received = 0
        try:
            sockets = [client, upstream]
            while True:
                ready, _, _ = select.select(sockets, [], [], server.timeout)
                if not ready:
                    break
                done = False
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        done = True
                        break
                    if source is client:
                        upstream.sendall(data); sent += len(data)
                    else:
                        client.sendall(data); received += len(data)
                if done:
                    break
        except OSError:
            pass
        finally:
            upstream.close()
            server.receipt("verdock.egress.allowed", {"host": host, "port": port, "sent": sent, "received": received}, True)
