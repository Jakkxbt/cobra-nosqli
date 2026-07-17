#!/usr/bin/env python3
import argparse, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

USERS = [{"username": "admin", "password": "secret"}]

def parse_value(data, field):
    if field in data: return data[field]
    obj = {}
    prefix = field + "["
    for key, val in data.items():
        if key.startswith(prefix) and key.endswith("]"): obj[key[len(prefix):-1]] = val
    return obj if obj else None

def matches(actual, wanted):
    if isinstance(wanted, dict):
        if "$ne" in wanted: return actual != wanted["$ne"]
        if "$gt" in wanted: return actual > wanted["$gt"]
        if "$regex" in wanted: return wanted["$regex"] == ".*"
    return actual == wanted

def handler(vulnerable):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            size = int(self.headers.get("Content-Length", 0)); raw = self.rfile.read(size)
            try:
                if "application/json" in self.headers.get("Content-Type", ""):
                    data = json.loads(raw or b"{}")
                else:
                    data = {k: v[-1] for k, v in parse_qs(raw.decode(), keep_blank_values=True).items()}
                username, password = parse_value(data, "username"), parse_value(data, "password")
                operators = [x for x in (username, password) if isinstance(x, dict)]
                if any("$where" in x for x in operators):
                    if vulnerable: return self.send(500, "MongoError: unexpected token in $where")
                    return self.send(400, "invalid input")
                if not vulnerable and operators: return self.send(400, "invalid input")
                ok = any(matches(u["username"], username) and matches(u["password"], password) for u in USERS)
                if ok:
                    self.send_response(302); self.send_header("Location", "/dashboard")
                    self.send_header("Set-Cookie", "session=lab-session; HttpOnly"); self.end_headers()
                else: self.send(200, "Invalid credentials")
            except Exception:
                self.send(400, "invalid input")
        def send(self, status, body):
            encoded = body.encode(); self.send_response(status); self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(encoded))); self.end_headers(); self.wfile.write(encoded)
    return Handler

def main(vulnerable):
    p = argparse.ArgumentParser(); p.add_argument("--port", type=int, required=True); a = p.parse_args()
    ThreadingHTTPServer(("127.0.0.1", a.port), handler(vulnerable)).serve_forever()
