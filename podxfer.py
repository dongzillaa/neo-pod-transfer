"""podxfer: one-shot file transfer between an iPhone (Safari) and a Runpod pod. Standard library only.

    python3 podxfer.py receive <dir>        # Safari uploads files into <dir>
    python3 podxfer.py send <file> [...]    # Safari downloads these files

Listens on 0.0.0.0:8888 (expose HTTP port 8888; open https://<pod-id>-8888.proxy.runpod.net). Prints a one-time
passphrase in the terminal: it is typed into a form (POST), never put in a URL, never logged. Five wrong
passphrases, the Done button or 20 minutes end the server. Never run it while the approval token is held.
"""
import hashlib, html, http.server, os, re, secrets, sys, threading, time, urllib.parse

PORT, MAX_BYTES, LIFETIME_S, MAX_FAILS = 8888, 100 * 2**20, 20 * 60, 5
MODE, ARGS = sys.argv[1], sys.argv[2:]
PASS = "-".join(secrets.token_hex(2) for _ in range(4))
SESSION = secrets.token_hex(32)
FILES = {f"f{i}": os.path.abspath(p) for i, p in enumerate(ARGS)} if MODE == "send" else {}
DEST = os.path.abspath(ARGS[0]) if MODE == "receive" else None
STATE = {"fails": 0, "done": False, "t0": time.monotonic()}
LOCK = threading.Lock()
NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def say(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


LOGIN = ("<form method=post action=/login><p>Passphrase from the pod terminal:</p>"
         "<input name=p autocomplete=off autocapitalize=off spellcheck=false><button>Enter</button></form>")
UPLOAD = """<p>Choose files, then tap the button. Each file shows name, size and SHA-256 when done.</p>
<input type=file id=f multiple><button id=up onclick=go()>Upload selected files</button><pre id=o></pre>
<form method=post action=/done><button>Done (stop the server)</button></form>
<script>async function go(){for(const f of document.getElementById('f').files){
const r=await fetch('/upload/'+encodeURIComponent(f.name),{method:'PUT',body:f});
document.getElementById('o').textContent+=await r.text()+'\\n';}}</script>"""


class H(http.server.BaseHTTPRequestHandler):
    timeout = 60                                # browsers keep idle spare connections open; never wait on them forever

    def log_message(self, *a):
        pass                                    # no request logging (paths only would be harmless; keep it silent)

    def authed(self):
        c = self.headers.get("Cookie", "")
        return any(secrets.compare_digest(p.strip(), f"s={SESSION}") for p in c.split(";"))

    def reply(self, code, body, ctype="text/html; charset=utf-8", extra=()):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        for k, v in (("Content-Type", ctype), ("Content-Length", str(len(data))), ("Cache-Control", "no-store"),
                     ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"), *extra):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def page(self):
        if MODE == "receive":
            return UPLOAD
        rows = "".join(f"<li><a href=/download/{k}>{html.escape(os.path.basename(p))}</a><br><code>{sha256(p)}</code></li>"
                       for k, p in FILES.items())
        return f"<p>Download from the pod:</p><ul>{rows}</ul><form method=post action=/done><button>Done (stop the server)</button></form>"

    def do_GET(self):
        if self.path == "/":
            return self.reply(200, self.page() if self.authed() else LOGIN)
        m = re.fullmatch(r"/download/(f\d+)", self.path)
        if MODE == "send" and m and self.authed() and m.group(1) in FILES:
            p = FILES[m.group(1)]
            with open(p, "rb") as f:
                data = f.read()
            say(f"sent {os.path.basename(p)} {len(data)} bytes")
            return self.reply(200, data, "application/octet-stream",
                              (("Content-Disposition", f'attachment; filename="{os.path.basename(p)}"'),))
        self.reply(404, "not found")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(n, 4096)).decode(errors="replace")
        if self.path == "/login":
            given = urllib.parse.parse_qs(body).get("p", [""])[0].strip().lower()
            if secrets.compare_digest(given, PASS):
                say("login ok")
                return self.reply(303, "", extra=(("Location", "/"),
                                  ("Set-Cookie", f"s={SESSION}; HttpOnly; Secure; SameSite=Strict; Path=/")))
            with LOCK:
                STATE["fails"] += 1
            say(f"login FAILED ({STATE['fails']}/{MAX_FAILS})")
            if STATE["fails"] >= MAX_FAILS:
                STATE["done"] = True
            return self.reply(403, "wrong passphrase")
        if self.path == "/done" and self.authed():
            STATE["done"] = True
            return self.reply(200, "server stopped; you can close this tab")
        self.reply(404, "not found")

    def do_PUT(self):
        m = re.fullmatch(r"/upload/([^/]+)", self.path)
        name = urllib.parse.unquote(m.group(1)) if m else ""
        n = int(self.headers.get("Content-Length") or -1)
        if MODE != "receive" or not self.authed() or not NAME.fullmatch(name) or not 0 <= n <= MAX_BYTES:
            return self.reply(400, "refused (login, name [A-Za-z0-9._-] or size)")
        target = os.path.join(DEST, name)
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return self.reply(409, f"{name}: already exists on the pod (not overwritten)")
        with os.fdopen(fd, "wb") as f:
            left = n
            while left:
                chunk = self.rfile.read(min(left, 1 << 20))
                if not chunk:
                    break
                f.write(chunk)
                left -= len(chunk)
        if left:
            os.unlink(target)
            return self.reply(400, f"{name}: upload incomplete, removed")
        digest = sha256(target)
        say(f"received {name} {n} bytes sha256 {digest}")
        self.reply(200, f"{name} {n} bytes sha256 {digest}", "text/plain; charset=utf-8")


def main():
    if MODE not in ("receive", "send") or not ARGS or (MODE == "receive" and not os.path.isdir(DEST)) or \
            (MODE == "send" and not all(os.path.isfile(p) for p in FILES.values())):
        sys.exit(__doc__)
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    say(f"podxfer {MODE} on port {PORT}; passphrase: {PASS}  (type it in Safari; it ends with the server)")
    while not STATE["done"] and time.monotonic() - STATE["t0"] < LIFETIME_S:
        time.sleep(0.5)
    time.sleep(1)                               # let the last reply reach Safari
    srv.shutdown()
    srv.server_close()
    say("podxfer stopped")


if __name__ == "__main__":
    main()
