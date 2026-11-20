#!/usr/bin/env python3
"""LAN forward proxy: plain HTTP forwarding + HTTPS CONNECT tunnelling.

Use only on networks you administer.

Security controls:
  * Client IP allow-list (default: loopback only)
  * Optional Basic proxy auth via the LANPROXY_AUTH env var ("user:pass")
  * Destinations must resolve to public IPs (blocks LAN / loopback /
    169.254.169.254 cloud metadata) unless --allow-private-destinations
  * DNS is resolved once and the vetted IP is dialled (no DNS-rebinding TOCTOU)
  * CONNECT restricted to an allow-list of ports (default 443)
  * Rejects ambiguous request framing (TE + CL) to prevent request smuggling
  * Logs host:port only, never full URLs (query strings often carry secrets)
"""
import argparse
import base64
import hmac
import ipaddress
import json
import logging
import os
import socket
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

BUF = 65536
# Hop-by-hop headers must not be forwarded (RFC 9110 §7.6.1). Host is rebuilt
# from the request URI; Expect is answered locally by BaseHTTPRequestHandler.
STRIP_HEADERS = {'connection', 'keep-alive', 'proxy-authenticate',
                 'proxy-authorization', 'proxy-connection', 'te', 'trailer',
                 'upgrade', 'host', 'expect'}


class ProxyError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'LANProxy/2.0'
    timeout = 60  # client socket timeout while reading request headers

    # ---------- logging / replies ----------
    def log_message(self, fmt, *args):
        logging.info('client=%s %s', self.client_address[0], fmt % args)

    def reply(self, status, payload, headers=None):
        data = json.dumps(payload, indent=2).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if getattr(self, 'command', None) != 'HEAD':
            self.wfile.write(data)
        self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        logging.warning('error=%s method=%s detail=%s', code,
                        getattr(self, 'command', None), message)
        self.reply(code, {'error': message or 'unsupported request'})

    # ---------- access control ----------
    def authorize(self):
        client_ip = self.client_address[0]
        try:
            client = ipaddress.ip_address(client_ip)
        except ValueError:
            self.reply(403, {'error': 'client not permitted'})
            return False
        if not any(client in net for net in self.server.allowed_clients):
            logging.warning('DENIED client=%s', client_ip)
            self.reply(403, {'error': 'client not permitted'})
            return False

        expected = self.server.proxy_auth
        if expected is not None:
            scheme, _, token = self.headers.get('Proxy-Authorization', '').partition(' ')
            if scheme.lower() != 'basic' or not hmac.compare_digest(
                    token.strip().encode(), expected):
                logging.warning('AUTH FAILED client=%s', client_ip)
                self.reply(407, {'error': 'proxy authentication required'},
                           {'Proxy-Authenticate': 'Basic realm="lanproxy"'})
                return False
        return True

    # ---------- upstream connection ----------
    def open_upstream(self, host, port):
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError):
            raise ProxyError(502, f'cannot resolve {host}')
        error = ProxyError(502, f'cannot connect to {host}:{port}')
        for family, socktype, proto, _, sockaddr in infos:
            ip = ipaddress.ip_address(sockaddr[0].split('%', 1)[0])
            if getattr(ip, 'ipv4_mapped', None):
                ip = ip.ipv4_mapped
            if not (self.server.allow_private or ip.is_global):
                error = ProxyError(403, f'destination {ip} is not a public address')
                continue
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(self.server.connect_timeout)
            try:
                sock.connect(sockaddr)  # dial the vetted IP, not the hostname
            except OSError:
                sock.close()
                continue
            sock.settimeout(self.server.idle_timeout)
            return sock
        raise error

    @staticmethod
    def pipe(read, sock_out):
        """Copy bytes until EOF/error, then half-close the destination."""
        try:
            while True:
                data = read(BUF)
                if not data:
                    break
                sock_out.sendall(data)
        except OSError:
            pass
        finally:
            try:
                sock_out.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    # ---------- HTTPS: CONNECT tunnel ----------
    def do_CONNECT(self):
        if not self.authorize():
            return
        try:
            url = urlsplit('//' + self.path)
            try:
                port = url.port
            except ValueError:
                raise ProxyError(400, 'invalid port')
            if not url.hostname or port is None:
                raise ProxyError(400, 'CONNECT target must be host:port')
            if port not in self.server.connect_ports:
                raise ProxyError(403, f'CONNECT to port {port} not permitted')
            upstream = self.open_upstream(url.hostname, port)
        except ProxyError as e:
            logging.warning('CONNECT refused client=%s target=%s: %s',
                            self.client_address[0], self.path, e)
            self.reply(e.status, {'error': str(e)})
            return

        logging.info('TUNNEL client=%s -> %s:%s', self.client_address[0],
                     url.hostname, port)
        self.send_response(200, 'Connection Established')
        self.end_headers()
        self.close_connection = True
        self.connection.settimeout(self.server.idle_timeout)

        # Read the client side via rfile.read1 so bytes already buffered
        # (e.g. a pipelined TLS ClientHello) are not lost.
        back = threading.Thread(target=self.pipe,
                                args=(upstream.recv, self.connection), daemon=True)
        back.start()
        self.pipe(self.rfile.read1, upstream)
        back.join()
        upstream.close()

    # ---------- plain HTTP forwarding ----------
    def build_request(self):
        url = urlsplit(self.path)
        if url.scheme != 'http' or not url.hostname:
            raise ProxyError(400, 'only http:// URLs are forwarded; HTTPS must use CONNECT')
        try:
            port = url.port or 80
        except ValueError:
            raise ProxyError(400, 'invalid port')
        if port not in self.server.http_ports:
            raise ProxyError(403, f'HTTP to port {port} not permitted')

        # Request framing: refuse anything ambiguous (request smuggling).
        te = self.headers.get_all('Transfer-Encoding') or []
        cl = self.headers.get_all('Content-Length') or []
        if te and cl:
            raise ProxyError(400, 'both Transfer-Encoding and Content-Length present')
        if te:
            codings = [c.strip().lower() for v in te for c in v.split(',')]
            if codings[-1] != 'chunked':
                raise ProxyError(400, 'unsupported transfer coding')
            body = 'chunked'
        elif cl:
            if len(set(v.strip() for v in cl)) != 1 or not cl[0].strip().isdigit():
                raise ProxyError(400, 'invalid Content-Length')
            body = int(cl[0])
        else:
            body = 0

        # Headers named in Connection are hop-by-hop too.
        drop = set(STRIP_HEADERS)
        for value in self.headers.get_all('Connection') or []:
            drop.update(t.strip().lower() for t in value.split(','))

        target = (url.path or '/') + (f'?{url.query}' if url.query else '')
        lines = [f'{self.command} {target} {self.request_version}',
                 f'Host: {url.netloc.rpartition("@")[2]}']
        lines += [f'{k}: {v}' for k, v in self.headers.items() if k.lower() not in drop]
        lines.append('Connection: close')
        head = ('\r\n'.join(lines) + '\r\n\r\n').encode('latin-1')
        return url.hostname, port, head, body

    def copy_exact(self, n, upstream):
        while n:
            data = self.rfile.read(min(n, BUF))
            if not data:
                raise ProxyError(400, 'request body truncated')
            upstream.sendall(data)
            n -= len(data)

    def copy_chunked(self, upstream):
        while True:
            line = self.rfile.readline(BUF + 1)
            if not line.endswith(b'\n') or len(line) > BUF:
                raise ProxyError(400, 'malformed chunk header')
            try:
                size = int(line.split(b';', 1)[0].strip(), 16)
            except ValueError:
                raise ProxyError(400, 'malformed chunk size')
            upstream.sendall(line)
            if size == 0:
                while True:  # trailers, terminated by an empty line
                    trailer = self.rfile.readline(BUF + 1)
                    if not trailer:
                        raise ProxyError(400, 'request body truncated')
                    upstream.sendall(trailer)
                    if trailer in (b'\r\n', b'\n'):
                        return
            self.copy_exact(size + 2, upstream)  # chunk data + CRLF

    def do_proxy(self):
        if not self.authorize():
            return
        if self.path.startswith('/'):  # addressed to the proxy itself
            if self.path == '/health' and self.command in ('GET', 'HEAD'):
                self.reply(200, {'status': 'listening', 'forwarding': True,
                                 'client_ip': self.client_address[0],
                                 'timestamp': datetime.now(timezone.utc).isoformat()})
            else:
                self.reply(400, {'error': 'configure this server as an HTTP proxy; '
                                          'requests must use absolute URLs'})
            return

        upstream = None
        try:
            host, port, head, body = self.build_request()
            upstream = self.open_upstream(host, port)
            upstream.sendall(head)
            if body == 'chunked':
                self.copy_chunked(upstream)
            elif body:
                self.copy_exact(body, upstream)
        except (ProxyError, OSError) as e:
            if upstream:
                upstream.close()
            status = e.status if isinstance(e, ProxyError) else 502
            logging.warning('HTTP refused client=%s: %s', self.client_address[0], e)
            try:
                self.reply(status, {'error': str(e) if isinstance(e, ProxyError)
                                    else 'upstream connection failed'})
            except OSError:
                pass
            return

        logging.info('HTTP client=%s %s %s:%s', self.client_address[0],
                     self.command, host, port)
        self.close_connection = True
        self.pipe(upstream.recv, self.connection)  # stream response verbatim
        upstream.close()

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_proxy


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--host', default='127.0.0.1',
                        help='bind address (use 0.0.0.0 or the LAN IP for other machines)')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--allow-client', action='append', default=['127.0.0.1/32'],
                        help='authorized client IP/CIDR; repeat as needed')
    parser.add_argument('--connect-port', action='append', type=int, default=[443],
                        help='extra port allowed for CONNECT (443 always allowed)')
    parser.add_argument('--http-port', action='append', type=int, default=[80],
                        help='extra port allowed for plain HTTP (80 always allowed)')
    parser.add_argument('--allow-private-destinations', action='store_true',
                        help='permit LAN/loopback/link-local destinations (SSRF risk)')
    parser.add_argument('--connect-timeout', type=float, default=10)
    parser.add_argument('--idle-timeout', type=float, default=300)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s | %(levelname)s | %(message)s')

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    server.allowed_clients = tuple(ipaddress.ip_network(c, strict=False)
                                   for c in args.allow_client)
    server.connect_ports = frozenset(args.connect_port)
    server.http_ports = frozenset(args.http_port)
    server.allow_private = args.allow_private_destinations
    server.connect_timeout = args.connect_timeout
    server.idle_timeout = args.idle_timeout

    creds = os.environ.get('LANPROXY_AUTH')
    server.proxy_auth = base64.b64encode(creds.encode()) if creds else None

    logging.info('Proxy listening on %s:%s', args.host, args.port)
    logging.info('Allowed clients: %s', ', '.join(map(str, server.allowed_clients)))
    logging.info('CONNECT ports: %s | HTTP ports: %s | private destinations: %s | auth: %s',
                 sorted(server.connect_ports), sorted(server.http_ports),
                 'ALLOWED' if server.allow_private else 'blocked',
                 'on' if server.proxy_auth else 'off')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info('Shutting down')
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
