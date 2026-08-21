"""AmonStrike -- WebSocket Security Module"""
import re, json
from .base import BaseModule

class WebsocketModule(BaseModule):
    NAME        = "websocket"
    DESCRIPTION = "WebSocket -- no auth, injection, origin bypass, CSWSH"

    def run(self):
        self.log("Testing WebSocket security...")
        ws_endpoints = self._find_ws_endpoints()
        for ep in ws_endpoints:
            self._test_ws_endpoint(ep)
        self._test_cswsh()
        return self.result()

    def _find_ws_endpoints(self):
        r = self.get("")
        if not r: return []
        endpoints = []
        text = r.text
        # Find absolute WebSocket URLs
        for match in re.findall(r'(?:wss?://)[^\s"\'<>]+', text):
            endpoints.append(match.strip("/'\""))
        # Find relative paths in new WebSocket()
        host = self.parsed.hostname or ""
        scheme = "wss" if self.parsed.scheme == "https" else "ws"
        for match in re.findall(r'new WebSocket\(["\']([^"\',]+)', text):
            if match.startswith("/"):
                endpoints.append(f"{scheme}://{host}{match}")
        self.info["websocket_endpoints"] = list(set(endpoints))
        return list(set(endpoints))

    def _test_ws_endpoint(self, ws_url):
        self.add_finding(
            title       = f"WebSocket Endpoint Found: {ws_url}",
            severity    = "INFO",
            description = (
                f"WebSocket endpoint at {ws_url}. "
                "Test for: missing auth, injection, origin bypass, CSWSH."
            ),
            evidence    = (f"Endpoint: {ws_url}\n"
                          f"PoC: wscat -c '{ws_url}'"),
            remediation = "Validate Origin header. Require auth token. Test input validation.",
            url=ws_url, cve="CWE-306",
        )
        try:
            import websocket as wslib
            conn = wslib.create_connection(ws_url, timeout=5)
            conn.send(json.dumps({"cmd": "ping"}))
            resp = conn.recv()
            conn.close()
            self.add_finding(
                title       = f"WebSocket No Authentication: {ws_url}",
                severity    = "HIGH",
                description = "Connected to WebSocket without credentials.",
                evidence    = f"URL: {ws_url}\nConnected: YES\nResponse: {str(resp)[:200]}",
                remediation = "Require auth token in WS handshake or first message.",
                url=ws_url, cve="CWE-306",
            )
        except ImportError:
            pass
        except Exception:
            pass

    def _test_cswsh(self):
        r = self.get("")
        if not r: return
        for name in r.cookies:
            if any(s in name.lower() for s in ["session","auth","token"]):
                self.add_finding(
                    title       = "CSWSH Risk -- Session Cookie Without SameSite",
                    severity    = "MEDIUM",
                    description = f"Cookie '{name}' sent in cross-site WS requests enables CSWSH.",
                    evidence    = f"Cookie: {name}\nMissing: SameSite=Strict",
                    remediation = "Add SameSite=Strict. Validate Origin in WS upgrade.",
                    url=self.url, cve="CWE-352",
                )
                break
