"""Socket-level controls for the shared command-admission loss fixture."""

import hashlib
import http.client
import http.server
import importlib.util
import json
from pathlib import Path
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
        self.server.requests.append((self.path, request))
        body = json.dumps({"command_id": "synthetic-command", "request_id": request["request_id"]}).encode()
        self.server.response_body = body
        self.send_response(self.server.response_status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class CommittedResponseLossTest(unittest.TestCase):
    def setUp(self):
        self.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        self.upstream.response_status = 202
        self.upstream.requests = []
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
            client.request("POST", path, body=json.dumps({"request_id": "synthetic-key"}),
                           headers={"Authorization": "Bearer synthetic-header-token"})
            response = client.getresponse()
            return response.status, json.loads(response.read())
        finally:
            client.close()

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
        self.assertEqual("synthetic-key", record["response"]["request_id"])
        self.assertNotIn("synthetic-header-token", json.dumps(self.proxy.records))
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
        for address in ("https://127.0.0.1:1234", "http://example.invalid:1234", "file:///tmp/fixture"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                CommittedResponseLoss(address)


if __name__ == "__main__":
    unittest.main()
