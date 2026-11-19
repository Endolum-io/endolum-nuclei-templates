"""Exercise the November 2026 build detectors with Nuclei and loopback HTTP only."""

import json
import os
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit


TEMPLATES = Path(__file__).resolve().parents[1] / "cves"
PLUS_API = "/api/9/nginx?fields=version,build"
APACHE_STATUS = "/server-status?auto"
OCTOBER_FIXES = {"123633", "123640"}
NOVEMBER_FIXES = {"113425", "120967", "121810", "123007", "123634", "125283"}
TLS = {"118899"}
PROXY_V2 = {"120993"}
ALL = OCTOBER_FIXES | NOVEMBER_FIXES | TLS | PROXY_V2 | {"119618"}


class Response(BaseHTTPRequestHandler):
    def do_GET(self):
        path, status, content_type, body = self.server.fixture
        if self.path != path:
            self.send_error(404)
            return
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


def fixtures():
    # R37 API build names omit the packaging revision (PLS.37.2.0.1 -> r37.2.0).
    for build, expected in [
        ("37.0.0", OCTOBER_FIXES | NOVEMBER_FIXES | TLS),
        ("37.0.6", OCTOBER_FIXES | NOVEMBER_FIXES | TLS),
        ("37.0.7", NOVEMBER_FIXES | TLS),
        ("37.0.8", set()),
        ("37.1.0", OCTOBER_FIXES | NOVEMBER_FIXES),
        ("37.1.1", OCTOBER_FIXES | NOVEMBER_FIXES),
        ("37.2.0", NOVEMBER_FIXES | TLS | PROXY_V2),
        ("37.3.0", set()),
        ("38.0.0", set()),
        ("37.0.70", set()),
        ("37.0.7-preview", set()),
        ("37.0.7.99", set()),
    ]:
        data = json.dumps({"version": "1.31.3", "build": "nginx-plus-r" + build})
        yield build, (PLUS_API, 200, "application/json", data), expected

    api = '{"build":"nginx-plus-r37.1.0","version":"1.31.3"}'
    for name, status, kind, body in [
        ("unrelated JSON", 200, "application/json", '{"version":"1.31.3","build":"other"}'),
        ("nested object", 200, "application/json", '{"example":' + api + '}'),
        ("missing build", 200, "application/json", '{"version":"1.31.3"}'),
        ("missing version", 200, "application/json", '{"build":"nginx-plus-r37.1.0"}'),
        ("invalid JSON", 200, "application/json", api[:-1]),
        ("HTML example", 200, "text/html", api),
        ("access denied", 403, "application/json", api),
    ]:
        yield name, (PLUS_API, status, kind, body), set()

    # These are the literal timestamps in Canonical's affected and fixed amd64 binaries.
    for version, affected, fixed in [
        ("2.4.52", "2026-10-16T01:03:19", "2026-11-12T13:00:12"),
        ("2.4.58", "2026-10-16T01:03:15", "2026-11-12T12:58:56"),
        ("2.4.66", "2026-10-16T01:03:06", "2026-11-12T12:57:38"),
        ("2.4.68", "2026-10-23T01:39:49", "2026-11-12T12:50:04"),
    ]:
        for timestamp, expected in [(affected, {"119618"}), (fixed, set())]:
            body = f"host\nServerVersion: Apache/{version} (Ubuntu)\nServerMPM: event\nServer Built: {timestamp}\n"
            yield f"{version} {timestamp}", (APACHE_STATUS, 200, "text/plain", body), expected
    for name, body in [
        ("bare version", "ServerVersion: Apache/2.4.58 (Ubuntu)\n"),
        ("different vendor", "ServerVersion: Apache/2.4.58 (Debian)\nServerMPM: event\nServer Built: 2026-10-16T01:03:15\n"),
        ("wrong pairing", "ServerVersion: Apache/2.4.52 (Ubuntu)\nServerMPM: event\nServer Built: 2026-10-16T01:03:15\n"),
        ("versionless", "ServerVersion: Apache\nServerMPM: event\nServer Built: 2026-10-16T01:03:15\n"),
    ]:
        yield name, (APACHE_STATUS, 200, "text/plain", body), set()


class DetectorTests(unittest.TestCase):
    def test_matches(self):
        with ExitStack() as stack:
            targets = []
            expected = {}
            names = {}
            for name, fixture, detections in fixtures():
                server = ThreadingHTTPServer(("127.0.0.1", 0), Response)
                stack.callback(server.server_close)
                server.fixture = fixture
                Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
                stack.callback(server.shutdown)
                port = server.server_port
                targets.append(f"http://127.0.0.1:{port}")
                expected[port] = detections
                names[port] = name

            temp = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            hosts = temp / "hosts"
            hosts.write_text("\n".join(targets) + "\n")
            command = [os.environ.get("NUCLEI_BINARY", "nuclei"), "-duc", "-ni", "-jsonl",
                       "-silent", "-no-stdin", "-timeout", "3", "-retries", "0", "-l", str(hosts)]
            for number in sorted(ALL):
                command.extend(["-t", str(TEMPLATES / f"CVE-2026-{number}.yaml")])
            result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=90)
            actual = {port: set() for port in expected}
            for line in result.stdout.splitlines():
                finding = json.loads(line)
                actual[urlsplit(finding["url"]).port].add(finding["template-id"].removeprefix("CVE-2026-"))
            for port, detections in expected.items():
                with self.subTest(fixture=names[port]):
                    self.assertEqual(actual[port], detections)


if __name__ == "__main__":
    unittest.main()
