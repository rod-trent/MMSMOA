#!/usr/bin/env python3
"""Mock Microsoft Graph security API, for building a SOC agent without a tenant.

MMS 2026 Midway Edition - "Empowering SOC Teams".

Serves the three endpoints a triage agent actually needs, at the same paths and
in the same response shapes as graph.microsoft.com:

    GET  /v1.0/security/incidents            [?$expand=alerts][&$filter=][&$top=]
    GET  /v1.0/security/incidents/{id}       [?$expand=alerts]
    GET  /v1.0/security/alerts_v2            [?$filter=][&$top=]
    POST /v1.0/security/runHuntingQuery

Point your client's base URL at http://localhost:8787/v1.0 and skip the
Authorization header. Everything else - paths, query parameters, JSON shapes,
enum spellings - matches the real thing, so the same code runs against both.

    python mock_graph_api.py [--port 8787] [--require-auth]

Standard library only, on purpose: this has to run on a locked-down corporate
laptop without asking anyone for permission.

NOT a security boundary. Binds to localhost, serves synthetic data, and does no
real token validation. Do not put it anywhere but your own machine.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def load_fixtures() -> tuple[list[dict], dict]:
    """Read the fixture files. Incidents are the single source of truth.

    alerts_v2 is derived from the incidents' expanded alerts rather than kept in
    its own file, so the two can never drift apart.
    """
    incidents_path = DATA_DIR / "graph-incidents.json"
    hunting_path = DATA_DIR / "hunting-responses.json"

    for path in (incidents_path, hunting_path):
        if not path.exists():
            sys.exit(f"Missing fixture: {path}")

    incidents = json.loads(incidents_path.read_text(encoding="utf-8"))["value"]
    hunting = json.loads(hunting_path.read_text(encoding="utf-8"))
    return incidents, hunting


def flatten_alerts(incidents: list[dict]) -> list[dict]:
    """Every alert across every incident, as /security/alerts_v2 returns them."""
    alerts: list[dict] = []
    for incident in incidents:
        alerts.extend(incident.get("alerts", []))
    return alerts


def strip_alerts(incident: dict) -> dict:
    """An incident as returned WITHOUT $expand=alerts.

    The real API omits the alerts key entirely unless you ask for it. Returning
    it anyway would let an agent work against the mock and then quietly break in
    production, which is the one thing a fixture server must not do.
    """
    return {k: v for k, v in incident.items() if k != "alerts"}


# ---------------------------------------------------------------------------
# A deliberately small $filter subset
# ---------------------------------------------------------------------------

# Supports:  field eq 'value'   and   field ge 2026-10-27T00:00:00Z
# joined by 'and'. That covers the filters a triage agent sends. Anything else
# raises, and the handler turns it into a Graph-shaped 400 rather than silently
# returning everything - a filter that is ignored is worse than one that fails.
_CLAUSE = re.compile(
    r"^\s*(?P<field>[A-Za-z][A-Za-z0-9_]*)\s+"
    r"(?P<op>eq|ne|ge|gt|le|lt)\s+"
    r"(?P<value>'[^']*'|[^\s]+)\s*$"
)


def _coerce(raw: str) -> str:
    return raw[1:-1] if raw.startswith("'") and raw.endswith("'") else raw


def apply_filter(rows: list[dict], expr: str) -> list[dict]:
    clauses = []
    for part in re.split(r"\s+and\s+", expr.strip(), flags=re.IGNORECASE):
        match = _CLAUSE.match(part)
        if not match:
            raise ValueError(f"Unsupported $filter clause: {part.strip()!r}")
        clauses.append((match["field"], match["op"].lower(), _coerce(match["value"])))

    def keep(row: dict) -> bool:
        for field, op, want in clauses:
            have = row.get(field)
            if have is None:
                return False
            have_s, want_s = str(have), str(want)
            if op == "eq" and have_s != want_s:
                return False
            if op == "ne" and have_s == want_s:
                return False
            if op == "ge" and have_s < want_s:
                return False
            if op == "gt" and have_s <= want_s:
                return False
            if op == "le" and have_s > want_s:
                return False
            if op == "lt" and have_s >= want_s:
                return False
        return True

    return [r for r in rows if keep(r)]


def match_hunting_query(hunting: dict, query: str) -> dict:
    """Pick the canned response whose 'match' substrings all appear in query."""
    lowered = (query or "").lower()
    for entry in hunting.get("queries", []):
        if all(token in lowered for token in entry.get("match", [])):
            return entry["response"]
    return hunting["default"]["response"]


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class GraphMockHandler(BaseHTTPRequestHandler):
    server_version = "MockGraphSecurity/1.0"

    incidents: list[dict] = []
    alerts: list[dict] = []
    hunting: dict = {}
    require_auth: bool = False

    # -- plumbing ----------------------------------------------------------

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # The React front end will call this from a different origin in dev.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, code: str, message: str) -> None:
        """Graph-shaped error, so your error handling is exercised too."""
        self._send(status, {"error": {"code": code, "message": message}})

    def _authorized(self) -> bool:
        if not self.require_auth:
            return True
        header = self.headers.get("Authorization", "")
        return header.startswith("Bearer ") and len(header) > len("Bearer ")

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("  %s\n" % (fmt % args))

    # -- routes ------------------------------------------------------------

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(200, {})

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = parse_qs(parsed.query)

        if path in ("", "/v1.0", "/v1.0/security"):
            return self._send(200, self._index())

        if not self._authorized():
            return self._error(
                401,
                "InvalidAuthenticationToken",
                "Access token is empty. Send 'Authorization: Bearer <anything>' or drop --require-auth.",
            )

        expand = "alerts" in query.get("$expand", [""])[0]

        incident_match = re.fullmatch(r"/v1\.0/security/incidents/([^/]+)", path)
        if incident_match:
            wanted = incident_match.group(1)
            for incident in self.incidents:
                if incident["id"] == wanted:
                    body = incident if expand else strip_alerts(incident)
                    return self._send(200, body)
            return self._error(
                404, "notFound", f"Incident '{wanted}' was not found in the fixtures."
            )

        if path == "/v1.0/security/incidents":
            rows = [i if expand else strip_alerts(i) for i in self.incidents]
            return self._collection(
                rows, query, "security/incidents" + ("(alerts())" if expand else "")
            )

        if path == "/v1.0/security/alerts_v2":
            if expand:
                return self._error(
                    400,
                    "BadRequest",
                    "$expand is not supported on /security/alerts_v2.",
                )
            return self._collection(list(self.alerts), query, "security/alerts_v2")

        return self._error(404, "notFound", f"No mock route for GET {parsed.path}")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if not self._authorized():
            return self._error(
                401, "InvalidAuthenticationToken", "Access token is empty."
            )

        if path != "/v1.0/security/runHuntingQuery":
            return self._error(404, "notFound", f"No mock route for POST {parsed.path}")

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            body = json.loads(raw)
        except json.JSONDecodeError as exc:
            return self._error(400, "BadRequest", f"Malformed JSON body: {exc}")

        # Graph spells this property with a capital Q and is case-sensitive.
        # Accept the lowercase form too, but say so, because the real API will
        # reject it and this is a cheap place to learn that.
        if "Query" in body:
            kql = body["Query"]
        elif "query" in body:
            kql = body["query"]
            sys.stderr.write(
                "  NOTE: body used 'query'. Graph expects 'Query' (capital Q).\n"
            )
        else:
            return self._error(
                400, "BadRequest", "Required property 'Query' is missing."
            )

        return self._send(200, match_hunting_query(self.hunting, kql))

    # -- helpers -----------------------------------------------------------

    def _collection(self, rows: list[dict], query: dict, context: str):
        try:
            if "$filter" in query:
                rows = apply_filter(rows, query["$filter"][0])
        except ValueError as exc:
            return self._error(400, "BadRequest", str(exc))

        if "$skip" in query:
            rows = rows[int(query["$skip"][0]) :]
        if "$top" in query:
            rows = rows[: int(query["$top"][0])]

        payload = {
            "@odata.context": f"https://graph.microsoft.com/v1.0/$metadata#{context}",
            "value": rows,
        }
        if "$count" in query and query["$count"][0].lower() == "true":
            payload["@odata.count"] = len(rows)
        return self._send(200, payload)

    def _index(self) -> dict:
        return {
            "service": "Mock Microsoft Graph security API",
            "note": "Synthetic data for MMS 2026 Midway - Empowering SOC Teams. Not a security boundary.",
            "routes": [
                "GET  /v1.0/security/incidents?$expand=alerts&$filter=severity eq 'high'&$top=5",
                "GET  /v1.0/security/incidents/48213?$expand=alerts",
                "GET  /v1.0/security/alerts_v2?$filter=serviceSource eq 'microsoftSentinel'",
                "POST /v1.0/security/runHuntingQuery   body: {\"Query\": \"SigninLogs | where ...\"}",
            ],
            "counts": {
                "incidents": len(self.incidents),
                "alerts": len(self.alerts),
                "huntingFixtures": len(self.hunting.get("queries", [])),
            },
        }


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def self_test() -> int:
    """Check the fixtures load and behave, without starting a server."""
    incidents, hunting = load_fixtures()
    alerts = flatten_alerts(incidents)
    failures: list[str] = []

    def check(label: str, ok: bool) -> None:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
        if not ok:
            failures.append(label)

    print("Fixture self-test")
    check("6 incidents loaded", len(incidents) == 6)
    check("9 alerts across those incidents", len(alerts) == 9)
    check(
        "every alert's incidentId matches its parent",
        all(
            a["incidentId"] == i["id"] for i in incidents for a in i.get("alerts", [])
        ),
    )
    check(
        "severity uses Graph casing",
        all(i["severity"] in {"unknown", "informational", "low", "medium", "high"} for i in incidents),
    )
    check(
        "status uses incidentStatus values",
        all(
            i["status"] in {"active", "resolved", "inProgress", "redirected", "awaitingAction"}
            for i in incidents
        ),
    )
    check(
        "alert status uses alertStatus values",
        all(a["status"] in {"unknown", "new", "inProgress", "resolved"} for a in alerts),
    )
    check(
        "strip_alerts removes the alerts key",
        "alerts" not in strip_alerts(incidents[0]),
    )
    check(
        "$filter severity eq 'high' returns 1 incident",
        len(apply_filter(incidents, "severity eq 'high'")) == 1,
    )
    check(
        "$filter on serviceSource finds Sentinel alerts",
        len(apply_filter(alerts, "serviceSource eq 'microsoftSentinel'")) == 3,
    )
    check(
        "unsupported $filter raises rather than returning everything",
        _raises(lambda: apply_filter(incidents, "contains(displayName,'x')")),
    )
    check(
        "hunting matcher finds the j.doe sign-ins",
        len(match_hunting_query(hunting, "SigninLogs | where UserPrincipalName == 'j.doe@contoso.com'")["results"]) == 3,
    )
    check(
        "unmatched query returns an empty result set, not invented rows",
        match_hunting_query(hunting, "DeviceProcessEvents | take 5")["results"] == [],
    )
    check(
        "incident 48176 still carries the injection payload",
        "Ignore prior instructions"
        in next(i for i in incidents if i["id"] == "48176")["description"],
    )

    print()
    if failures:
        print(f"{len(failures)} check(s) failed.")
        return 1
    print("All checks passed.")
    return 0


def _raises(fn) -> bool:
    try:
        fn()
    except ValueError:
        return True
    return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument(
        "--require-auth",
        action="store_true",
        help="Reject calls with no Bearer header, so you exercise your token path.",
    )
    parser.add_argument(
        "--self-test", action="store_true", help="Validate the fixtures and exit."
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    incidents, hunting = load_fixtures()
    GraphMockHandler.incidents = incidents
    GraphMockHandler.alerts = flatten_alerts(incidents)
    GraphMockHandler.hunting = hunting
    GraphMockHandler.require_auth = args.require_auth

    base = f"http://localhost:{args.port}/v1.0"
    print("Mock Microsoft Graph security API")
    print(f"  base URL   {base}")
    print(f"  incidents  {len(incidents)}")
    print(f"  alerts     {len(GraphMockHandler.alerts)}")
    print(f"  auth       {'Bearer required' if args.require_auth else 'not required'}")
    print()
    print("  Set GRAPH_BASE_URL to the base URL above and run your agent unchanged.")
    print("  Ctrl-C to stop.")
    print()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), GraphMockHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
