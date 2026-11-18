"""Forward ARTEX's container-local 127.0.0.1:3000 to BlankSuite on the Mac.

Only the fixed host.docker.internal:3000 destination is used. This preserves the
127.0.0.1:3000 Host header that BlankSuite's local authority profile requires.
"""

from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DESTINATION = "host.docker.internal"
PORT = 3000
MAX_BODY = 10 * 1024 * 1024
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        pass  # Paths and headers can contain auth data; do not log them.

    def forward(self):
        if not self.path.startswith("/") or self.path.startswith("//"):
            self.send_error(400, "expected a local path")
            return
        if self.headers.get("Transfer-Encoding"):
            self.send_error(400, "chunked request bodies are not supported")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "invalid content length")
            return
        if length < 0 or length > MAX_BODY:
            self.send_error(413, "request body too large")
            return
        body = self.rfile.read(length) if length else None
        headers = {name: value for name, value in self.headers.items() if name.lower() not in HOP_HEADERS and name.lower() != "host"}
        headers["Host"] = "127.0.0.1:3000"
        conn = HTTPConnection(DESTINATION, PORT, timeout=20)
        try:
            conn.request(self.command, self.path, body=body, headers=headers)
            response = conn.getresponse()
            self.send_response_only(response.status, response.reason)
            for name, value in response.getheaders():
                if name.lower() not in HOP_HEADERS:
                    self.send_header(name, value)
            self.send_header("Connection", "close")
            self.end_headers()
            while chunk := response.read(64 * 1024):
                self.wfile.write(chunk)
        except (OSError, TimeoutError):
            self.send_error(502, "local app unavailable")
        finally:
            conn.close()
            self.close_connection = True

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = forward


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
