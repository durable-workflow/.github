"""Loopback test proxy: consume an upstream success, then lose one response.

No credentials are recorded. arm(method, path) selects exactly one request;
only its complete 2xx upstream response is dropped. Other traffic is forwarded.
The caller owns server.shutdown()/server_close(), upstream and synthetic data.
"""
import hashlib
import http.client
import http.server
import json
import socket
import threading
import urllib.parse


class CommittedResponseLoss(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, upstream):
        parsed = urllib.parse.urlsplit(upstream)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise ValueError("fixture upstream must be loopback HTTP")
        self.upstream = (parsed.hostname, parsed.port or 80)
        self.records = []
        self.armed = None
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _Handler)

    def arm(self, method, path):
        with self.lock:
            if self.armed is not None:
                raise ValueError("a response loss is already armed")
            self.armed = (method, path)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_port}"


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def forward(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with self.server.lock:
            selected = self.server.armed == (self.command, self.path)
            if selected:
                self.server.armed = None
        upstream = http.client.HTTPConnection(*self.server.upstream, timeout=40)
        try:
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in {"host", "connection", "transfer-encoding"}}
            upstream.request(self.command, self.path, body=raw or None, headers=headers)
            response = upstream.getresponse()
            body = response.read()  # Complete upstream response BEFORE losing it.
            try:
                request_json = json.loads(raw) if raw else None
                response_json = json.loads(body) if body else None
            except (ValueError, UnicodeError):
                request_json = response_json = None
            drop = selected and 200 <= response.status < 300
            record = {"method": self.command, "path": self.path,
                      "upstream_status": response.status, "upstream_body_bytes": len(body),
                      "upstream_body_sha256": hashlib.sha256(body).hexdigest(),
                      "request": request_json, "response": response_json, "dropped": drop}
            with self.server.lock:
                self.server.records.append(record)
            if drop:
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in {"content-length", "transfer-encoding", "connection", "server", "date"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        finally:
            upstream.close()

    do_GET = forward
    do_POST = forward
