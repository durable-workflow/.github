"""Bounded loopback fixture: consume upstream success, then lose one response."""
import hashlib
import http.client
import http.server
import re
import socket
import threading


MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 1_048_576
SOCKET_TIMEOUT_SECONDS = 40


def origin_path(path):
    return (isinstance(path, str) and len(path) <= 4096 and not path.startswith("//")
            and re.fullmatch(r"/[^\x00-\x20\x7f#]*", path) is not None)


def content_length(headers, required):
    values = headers.get_all("Content-Length", [])
    if not values and not required:
        return None
    if len(values) != 1 or re.fullmatch(r"0|[1-9][0-9]{0,6}", values[0]) is None:
        raise ValueError("A single canonical bounded Content-Length is required")
    return int(values[0])


class RequestRefused(ValueError):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status


class CommittedResponseLoss(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, upstream):
        match = re.fullmatch(r"http://127\.0\.0\.1:([1-9][0-9]{0,4})", upstream) if isinstance(upstream, str) else None
        if match is None or not 1 <= int(match.group(1)) <= 65535:
            raise ValueError("Fixture upstream must be canonical numeric loopback HTTP with an explicit port")
        self.upstream_port = int(match.group(1))
        self.records = []
        self.armed = None
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _Handler)

    def arm(self, method, path):
        if method not in {"GET", "POST"} or not origin_path(path):
            raise ValueError("Arm requires an exact supported method and origin-form path")
        with self.lock:
            if self.armed is not None:
                raise ValueError("a response loss is already armed")
            self.armed = (method, path)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_port}"


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        # Evidence uses closed metadata records rather than HTTP request logs.
        pass

    def send_error(self, code, message=None, explain=None):
        # Base parser messages can include an untrusted raw request line.
        reasons = {400: "Fixture request framing refused", 413: "Fixture byte cap exceeded",
                   501: "Fixture method unsupported", 502: "Fixture upstream response unverified"}
        super().send_error(code, reasons.get(code, "Fixture request refused"),
                           "The fixture refused the request without retaining its content.")

    def request_body(self):
        original_path = self.requestline.split()[1]
        if (self.request_version not in {"HTTP/1.0", "HTTP/1.1"} or original_path != self.path
                or not origin_path(original_path) or self.headers.get_all("Transfer-Encoding", [])):
            raise RequestRefused(400, "Fixture requires an origin path and no request transfer encoding")
        try:
            length = content_length(self.headers, self.command == "POST")
        except ValueError as error:
            raise RequestRefused(400, "Fixture request length is invalid") from error
        if self.command == "GET" and length not in (None, 0):
            raise RequestRefused(400, "Fixture GET requests must be bodyless")
        length = length or 0
        if length > MAX_REQUEST_BYTES:
            raise RequestRefused(413, "Fixture request exceeds its fixed byte cap")
        self.connection.settimeout(SOCKET_TIMEOUT_SECONDS)
        try:
            body = self.rfile.read(length)
        except OSError as error:
            raise RequestRefused(400, "Fixture request body is incomplete") from error
        if len(body) != length:
            raise RequestRefused(400, "Fixture request body is incomplete")
        return body

    def response_body(self, response):
        encodings = response.headers.get_all("Transfer-Encoding", [])
        length = content_length(response.headers, False)
        if encodings and (encodings != ["chunked"] or length is not None):
            raise ValueError("Fixture upstream framing is unsupported")
        if length is not None and length > MAX_RESPONSE_BYTES:
            raise ValueError("Fixture upstream response exceeds its fixed byte cap")
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES or (length is not None and len(body) != length):
            raise ValueError("Fixture upstream body is oversized or incomplete")
        if response.read(1):
            raise ValueError("Fixture upstream body exceeds its fixed byte cap")
        return body

    def upstream_response(self, raw):
        # The destination address is literal; only the validated port varies.
        upstream = http.client.HTTPConnection("127.0.0.1", self.server.upstream_port,
                                              timeout=SOCKET_TIMEOUT_SECONDS)
        try:
            upstream.connect()
            if upstream.sock.getpeername()[0] != "127.0.0.1":
                raise ValueError("Fixture upstream peer is not loopback")
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in {"host", "connection", "transfer-encoding", "proxy-authorization"}}
            headers["Connection"] = "close"
            upstream.request(self.command, self.path, body=raw or None, headers=headers)
            response = upstream.getresponse()
            body = self.response_body(response)
            return response.status, response.getheaders(), body
        finally:
            upstream.close()

    def refuse(self, status):
        self.close_connection = True
        try:
            self.send_error(status)
        except OSError:
            # A failed client may already have closed its side of the fixture.
            pass

    def forward(self):
        try:
            raw = self.request_body()
        except RequestRefused as error:
            self.refuse(error.status)
            return
        with self.server.lock:
            selected = self.server.armed == (self.command, self.path)
            if selected:
                self.server.armed = None
        try:
            status, headers, body = self.upstream_response(raw)
        except (http.client.HTTPException, OSError, ValueError):
            self.refuse(502)
            return
        drop = selected and 200 <= status < 300
        record = {"method": self.command, "path": self.path,
                  "request_body_bytes": len(raw), "request_body_sha256": hashlib.sha256(raw).hexdigest(),
                  "upstream_status": status, "upstream_complete": True,
                  "upstream_body_bytes": len(body), "upstream_body_sha256": hashlib.sha256(body).hexdigest(),
                  "dropped": drop}
        with self.server.lock:
            self.server.records.append(record)
        self.close_connection = True
        try:
            if drop:
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            self.send_response(status)
            for key, value in headers:
                if key.lower() not in {"content-length", "transfer-encoding", "connection", "server", "date"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            # Unplanned client loss is never recorded as intentional injection.
            pass

    do_GET = forward
    do_POST = forward
