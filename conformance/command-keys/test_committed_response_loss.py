"""Socket-level controls for the shared command-admission loss fixture."""

import hashlib
import http.client
import http.server
import importlib.util
import json
from pathlib import Path
import socket
import threading
import unittest


SOURCE = Path(__file__).with_name("committed_response_loss.py")
SPEC = importlib.util.spec_from_file_location("committed_response_loss", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
CommittedResponseLoss = MODULE.CommittedResponseLoss


class Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_arguments):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.reply(request)

    def do_GET(self):
        self.reply({"request_id": "synthetic-get"})

    def reply(self, request):
        self.server.requests.append((self.path, request))
        self.close_connection = True
        if self.server.fail_before_headers:
            return
        document = {"command_id": "synthetic-command", "request_id": request["request_id"],
                    "unexpected_secret": "synthetic-response-secret"}
        body = self.server.body_override or json.dumps(document).encode()
        self.server.response_body = body
        self.send_response(self.server.response_status)
        if self.server.framing in {"chunked", "incomplete-chunked"}:
            self.send_header("Transfer-Encoding", "chunked")
            body = f"{len(body):x}\r\n".encode() + body + b"\r\n"
            if self.server.framing == "chunked":
                body += b"0\r\n\r\n"
        elif self.server.framing == "length":
            length = self.server.length_override
            self.send_header("Content-Length", str(len(body) if length is None else length))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            # A refusal may close the proxy before this synthetic writer ends.
            pass


class CommittedResponseLossTest(unittest.TestCase):
    def setUp(self):
        self.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        self.upstream.response_status = 202
        self.upstream.requests = []
        self.upstream.fail_before_headers = False
        self.upstream.body_override = None
        self.upstream.length_override = None
        self.upstream.framing = "length"
        self.serve(self.upstream)
        self.proxy = CommittedResponseLoss(f"http://127.0.0.1:{self.upstream.server_port}")
        self.serve(self.proxy)

    def serve(self, server):
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()

        def close():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.addCleanup(close)

    def request(self, path="/commit"):
        client = http.client.HTTPConnection("127.0.0.1", self.proxy.server_port, timeout=2)
        try:
            client.request("POST", path, body=json.dumps({"request_id": "synthetic-key", "token": "synthetic-request-secret"}),
                           headers={"Authorization": "Bearer synthetic-header-token"})
            response = client.getresponse()
            return response.status, json.loads(response.read())
        finally:
            client.close()

    def raw_request(self, headers, body=b"", path="/commit", method="POST"):
        with socket.create_connection(("127.0.0.1", self.proxy.server_port), timeout=2) as client:
            head = f"{method} {path} HTTP/1.1\r\nHost: fixture\r\n{headers}\r\n"
            client.sendall(head.encode("ascii") + body)
            client.shutdown(socket.SHUT_WR)
            response = http.client.HTTPResponse(client)
            response.begin()
            return response.status, response.read(8192)

    def test_complete_upstream_success_precedes_loss_before_client_status_line(self):
        self.proxy.arm("POST", "/commit")
        with self.assertRaises(http.client.RemoteDisconnected):
            self.request()
        self.assertEqual(1, len(self.upstream.requests))
        record = self.proxy.records[0]
        self.assertEqual(202, record["upstream_status"])
        self.assertTrue(record["dropped"])
        self.assertEqual(len(self.upstream.response_body), record["upstream_body_bytes"])
        self.assertEqual(hashlib.sha256(self.upstream.response_body).hexdigest(), record["upstream_body_sha256"])
        self.assertTrue(record["upstream_complete"])
        self.assertEqual({"method", "path", "request_body_bytes", "request_body_sha256", "upstream_status",
                          "upstream_complete", "upstream_body_bytes", "upstream_body_sha256", "dropped"}, set(record))
        self.assertNotIn("synthetic-header-token", json.dumps(self.proxy.records))
        self.assertNotIn("synthetic-request-secret", json.dumps(self.proxy.records))
        self.assertNotIn("synthetic-response-secret", json.dumps(self.proxy.records))
        self.assertNotIn("synthetic-key", json.dumps(self.proxy.records))
        status, body = self.request()
        self.assertEqual(202, status)
        self.assertEqual("synthetic-command", body["command_id"])
        self.assertEqual(2, len(self.upstream.requests))
        self.assertFalse(self.proxy.records[1]["dropped"])

    def test_loss_is_one_shot_for_only_the_exact_method_and_path(self):
        self.proxy.arm("POST", "/commit")
        with self.assertRaises(ValueError):
            self.proxy.arm("POST", "/another")
        self.assertEqual(202, self.request("/different")[0])
        self.assertFalse(self.proxy.records[0]["dropped"])
        with self.assertRaises(http.client.RemoteDisconnected):
            self.request()
        self.assertEqual(2, len(self.upstream.requests))
        self.assertTrue(self.proxy.records[1]["dropped"])

    def test_selected_non_success_is_forwarded_and_not_retried(self):
        self.upstream.response_status = 409
        self.proxy.arm("POST", "/commit")
        self.assertEqual(409, self.request()[0])
        self.assertEqual(1, len(self.upstream.requests))
        self.assertFalse(self.proxy.records[0]["dropped"])
        self.assertIsNone(self.proxy.armed)

    def test_upstream_must_be_loopback_http(self):
        for address in ("https://127.0.0.1:1234", "http://example.invalid:1234", "file:///tmp/fixture",
                        "http://localhost:1234", "http://127.0.0.2:1234", "http://127.0.0.1",
                        "http://user:password@127.0.0.1:1234", "http://127.0.0.1:1234/",
                        "http://127.0.0.1:1234?q=x", "http://127.0.0.1:1234#fragment",
                        "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:0123", None):
            with self.subTest(address=address), self.assertRaises(ValueError):
                CommittedResponseLoss(address)

    def test_invalid_request_framing_is_refused_before_forwarding(self):
        cases = [("", b"", 400), ("Content-Length: -1\r\n", b"", 400),
                 ("Content-Length: 01\r\n", b"x", 400), ("Content-Length: 1 \r\n", b"x", 400),
                 ("Content-Length: 0\r\nContent-Length: 0\r\n", b"", 400),
                 (f"Content-Length: {MODULE.MAX_REQUEST_BYTES + 1}\r\n", b"", 413),
                 ("Transfer-Encoding: chunked\r\nContent-Length: 0\r\n", b"", 400),
                 ("Content-Length: 2\r\n", b"x", 400)]
        for headers, body, status in cases:
            with self.subTest(headers=headers):
                self.assertEqual(status, self.raw_request(headers, body)[0])
                self.assertEqual([], self.upstream.requests)
                self.assertEqual([], self.proxy.records)

    def test_only_origin_form_paths_can_be_forwarded_or_armed(self):
        for path in ("http://example.invalid/", "//example.invalid/", "/path#fragment"):
            with self.subTest(path=path):
                self.assertEqual(400, self.raw_request("Content-Length: 0\r\n", path=path)[0])
                self.assertEqual([], self.upstream.requests)
                with self.assertRaises(ValueError):
                    self.proxy.arm("POST", path)

    def test_bodyless_get_needs_no_content_length(self):
        status, body = self.raw_request("", method="GET")
        self.assertEqual(202, status)
        self.assertEqual("synthetic-get", json.loads(body)["request_id"])
        self.assertEqual(0, self.proxy.records[0]["request_body_bytes"])

    def test_parser_errors_do_not_echo_request_content(self):
        marker = "synthetic-private-request-line"
        for method, path in (("POST " + marker, "/commit"), ("POST", "/" + marker + "#fragment")):
            with self.subTest(method=method, path=path):
                status, body = self.raw_request("Content-Length: 0\r\n", method=method, path=path)
                self.assertEqual(400, status)
                self.assertNotIn(marker.encode(), body)
                self.assertEqual([], self.proxy.records)
                self.assertEqual([], self.upstream.requests)

    def test_oversized_or_incomplete_upstream_is_not_an_injected_loss(self):
        body = b'{"request_id":"synthetic-key"}'
        marker = b"private-upstream-body"
        oversized = marker + b"x" * (MODULE.MAX_RESPONSE_BYTES + 1 - len(marker))
        cases = [("length", MODULE.MAX_RESPONSE_BYTES + 1, marker, False),
                 ("close", None, oversized, False),
                 ("length", 40, marker, False),
                 ("incomplete-chunked", None, marker, False),
                 ("length", None, marker, True)]
        for framing, length, response, fail in cases:
            with self.subTest(framing=framing, length=length, fail=fail):
                self.upstream.framing = framing
                self.upstream.length_override = length
                self.upstream.body_override = response
                self.upstream.fail_before_headers = fail
                self.proxy.arm("POST", "/commit")
                status, reply = self.raw_request(f"Content-Length: {len(body)}\r\n", body)
                self.assertEqual(502, status)
                self.assertNotIn(marker, reply)
                self.assertEqual([], self.proxy.records)
                self.assertIsNone(self.proxy.armed)

    def test_complete_chunked_upstream_can_supply_a_bounded_loss(self):
        self.upstream.framing = "chunked"
        self.proxy.arm("POST", "/commit")
        with self.assertRaises(http.client.RemoteDisconnected):
            self.request()
        self.assertTrue(self.proxy.records[0]["dropped"])
        self.assertTrue(self.proxy.records[0]["upstream_complete"])


if __name__ == "__main__":
    unittest.main()
