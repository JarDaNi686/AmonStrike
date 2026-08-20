"""
AmonStrike — ASN Infrastructure Mapper
Level 1: Map entire IP space of a target organization.

Org → ASN → CIDR ranges → live hosts → new domains

This finds assets nobody else sees.
Every IP range = potential new attack surface.
"""

import re
import sys
import json
import socket
import subprocess
import ipaddress
import requests
from datetime import datetime
from typing import List, Dict, Set

sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.dirname(__file__)))


class ASNMapper:
    """
    Maps target organization's complete IP infrastructure via ASN.

    Workflow:
      domain → WHOIS → ASN numbers
      ASN → CIDR prefixes (BGPView API)
      CIDRs → live hosts (masscan/naabu)
      live hosts → reverse DNS → new domains
      live hosts → SSL certs → new SANs
    """

    BGPVIEW_API   = "https://api.bgpview.io"
    IPINFO_API    = "https://ipinfo.io"
    HACKERTARGET  = "https://api.hackertarget.com"

    def __init__(self, target: str, timeout: int = 15):
        # Accept domain or org name
        self.target  = target
        self.domain  = target.replace("https://","").replace("http://","").split("/")[0]
        self.timeout = timeout
        self.results = {
            "target":   target,
            "asns":     [],
            "cidrs":    [],
            "live_ips": [],
            "new_domains": [],
            "timestamp": datetime.now().isoformat(),
        }

    def run(self) -> dict:
        """Run full ASN mapping."""
        print(f"\n[*] ASN Infrastructure Mapping: {self.target}")

        # Step 1: Find ASNs
        asns = self._find_asns()
        self.results["asns"] = asns
        print(f"  [+] ASNs found: {[a['asn'] for a in asns]}")

        # Step 2: Get CIDR ranges
        cidrs = self._asns_to_cidrs(asns)
        self.results["cidrs"] = cidrs
        print(f"  [+] CIDR ranges: {len(cidrs)}")

        # Step 3: Reverse IP → domains
        domains = self._reverse_ip_lookup()
        self.results["new_domains"] = domains
        if domains:
            print(f"  [+] Reverse DNS found: {len(domains)} domains")

        # Step 4: Summary
        total_ips = sum(
            ipaddress.ip_network(c, strict=False).num_addresses
            for c in cidrs if c
        )
        print(f"  [i] Total IP space: {total_ips:,} addresses across {len(cidrs)} CIDRs")
        print(f"  [i] Scan command:")
        if cidrs:
            print(f"      masscan -p 80,443,8080,8443 {' '.join(cidrs[:3])} --rate=1000")

        return self.results

    def _find_asns(self) -> List[Dict]:
        """Find ASN numbers for the target organization."""
        asns = []

        # Method 1: BGPView organization search
        try:
            r = requests.get(
                f"{self.BGPVIEW_API}/search",
                params={"query_term": self.domain},
                timeout=self.timeout
            )
            if r.status_code == 200:
                data = r.json()
                for asn in data.get("data",{}).get("asns",[]):
                    entry = {
                        "asn":         f"AS{asn.get('asn','')}",
                        "name":        asn.get("name",""),
                        "description": asn.get("description",""),
                        "country":     asn.get("country_code",""),
                        "source":      "bgpview",
                    }
                    asns.append(entry)
        except Exception:
            pass

        # Method 2: ipinfo.io lookup for domain's IP
        if not asns:
            try:
                ip = socket.gethostbyname(self.domain)
                r  = requests.get(
                    f"{self.IPINFO_API}/{ip}/json",
                    timeout=self.timeout
                )
                if r.status_code == 200:
                    data = r.json()
                    if "org" in data:
                        # Format: "AS12345 Org Name"
                        parts = data["org"].split(" ",1)
                        asns.append({
                            "asn":         parts[0],
                            "name":        parts[1] if len(parts)>1 else "",
                            "description": data.get("company",""),
                            "country":     data.get("country",""),
                            "source":      "ipinfo",
                        })
            except Exception:
                pass

        # Method 3: WHOIS-based lookup
        if not asns:
            try:
                out = subprocess.run(
                    ["whois", self.domain],
                    capture_output=True, text=True, timeout=15
                ).stdout
                for match in re.findall(r'AS(\d+)', out):
                    asns.append({
                        "asn":    f"AS{match}",
                        "name":   self.domain,
                        "source": "whois",
                    })
            except Exception:
                pass

        # Deduplicate
        seen = set()
        unique = []
        for a in asns:
            if a["asn"] not in seen:
                seen.add(a["asn"])
                unique.append(a)
        return unique[:10]  # Limit to 10 ASNs

    def _asns_to_cidrs(self, asns: List[Dict]) -> List[str]:
        """Convert ASNs to CIDR ranges."""
        cidrs = []
        for asn_entry in asns:
            asn_num = asn_entry["asn"].lstrip("AS")
            try:
                r = requests.get(
                    f"{self.BGPVIEW_API}/asn/{asn_num}/prefixes",
                    timeout=self.timeout
                )
                if r.status_code != 200:
                    continue
                data = r.json().get("data",{})
                for prefix in data.get("ipv4_prefixes",[]):
                    cidr = prefix.get("prefix","")
                    if cidr:
                        cidrs.append(cidr)
                        asn_entry.setdefault("cidrs",[]).append(cidr)
            except Exception:
                pass

        # Deduplicate
        return list(set(cidrs))[:100]  # Limit

    def _reverse_ip_lookup(self) -> List[str]:
        """Reverse IP lookup to find domains hosted on same IPs."""
        domains = set()

        try:
            ip = socket.gethostbyname(self.domain)
            # HackerTarget reverse IP
            r = requests.get(
                f"{self.HACKERTARGET}/reverseiplookup/",
                params={"q": ip},
                timeout=self.timeout
            )
            if r.status_code == 200 and "error" not in r.text.lower():
                for domain in r.text.strip().splitlines():
                    domain = domain.strip()
                    if domain and "." in domain:
                        domains.add(domain)
        except Exception:
            pass

        return sorted(domains)

    def get_masscan_command(self) -> str:
        """Generate masscan command for the discovered CIDRs."""
        if not self.results["cidrs"]:
            return ""
        cidrs = " ".join(self.results["cidrs"][:20])
        return (
            f"masscan -p 80,443,8080,8443,8888,3000,5000,9200,6379,27017,5432,3306 "
            f"{cidrs} --rate=1000 -oJ masscan_results.json"
        )

    def get_naabu_command(self) -> str:
        """Generate naabu command for discovered CIDRs."""
        if not self.results["cidrs"]:
            return ""
        # Write CIDRs to temp file approach
        return (
            "echo '" + "\\n".join(self.results["cidrs"][:20]) + "' | "
            "naabu -p 80,443,8080,8443,3000,8888,9200,6379 -silent | "
            "httpx -silent -title -tech-detect"
        )


class CloudBucketHunter:
    """
    Enumerates cloud storage buckets (S3/Azure/GCP).
    Name permutation engine based on target domain.
    """

    S3_REGIONS = [
        "us-east-1","us-east-2","us-west-1","us-west-2",
        "eu-west-1","eu-central-1","ap-southeast-1","ap-northeast-1",
    ]

    def __init__(self, domain: str, threads: int = 20):
        self.domain   = domain.split(".")[0]  # Use first label
        self.threads  = threads
        self.session  = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0"

    def generate_names(self) -> List[str]:
        """Generate bucket name permutations."""
        base     = self.domain.lower().replace(".", "-")
        suffixes = [
            "", "-dev", "-prod", "-staging", "-test", "-backup",
            "-backups", "-data", "-assets", "-media", "-uploads",
            "-logs", "-static", "-public", "-private", "-internal",
            "-files", "-images", "-docs", "-api", "-admin",
            "-web", "-app", "-mail", "-email", "-database",
            "-db", "-archive", "-config", "-secrets", "-keys",
            "-credentials", "-deploy", "-release", "-build",
            "-ci", "-cdn", "-storage", "-bucket", "-s3",
        ]
        prefixes = [
            "", "dev-", "prod-", "staging-", "test-",
            "backup-", "static-", "media-", "assets-",
        ]

        names = set()
        for prefix in prefixes:
            for suffix in suffixes:
                names.add(f"{prefix}{base}{suffix}")
                # Also try with year
                names.add(f"{prefix}{base}{suffix}-2024")
                names.add(f"{prefix}{base}{suffix}-2025")

        return sorted(names)

    def check_s3(self, bucket_name: str) -> dict:
        """Check if S3 bucket exists and is readable."""
        result = {"bucket": bucket_name, "exists": False, "readable": False,
                  "writable": False, "url": "", "provider": "s3"}

        url = f"https://{bucket_name}.s3.amazonaws.com/"
        try:
            r = self.session.get(url, timeout=5)
            if r.status_code == 200:
                result["exists"]   = True
                result["readable"] = True
                result["url"]      = url
                # Try to list
                if "ListBucketResult" in r.text:
                    result["files"] = re.findall(r'<Key>(.*?)</Key>', r.text)[:20]
            elif r.status_code == 403:
                result["exists"] = True  # Exists but private
                result["url"]    = url
            elif r.status_code == 301:
                result["exists"] = True
                result["url"]    = url
        except Exception:
            pass

        return result

    def check_azure(self, name: str) -> dict:
        """Check Azure blob storage container."""
        result = {"bucket": name, "exists": False, "readable": False,
                  "url": "", "provider": "azure"}

        for container in ["", "uploads", "public", "files", "media"]:
            suffix = f"/{container}" if container else ""
            url    = f"https://{name}.blob.core.windows.net{suffix}?restype=container&comp=list"
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code == 200:
                    result.update({
                        "exists":   True,
                        "readable": True,
                        "url":      url,
                    })
                    return result
                elif r.status_code == 403:
                    result["exists"] = True
                    result["url"]    = url
            except Exception:
                pass
        return result

    def check_gcp(self, name: str) -> dict:
        """Check GCP storage bucket."""
        result = {"bucket": name, "exists": False, "readable": False,
                  "url": "", "provider": "gcp"}

        url = f"https://storage.googleapis.com/{name}/"
        try:
            r = self.session.get(url, timeout=5)
            if r.status_code == 200:
                result.update({
                    "exists":   True,
                    "readable": True,
                    "url":      url,
                })
            elif r.status_code == 403:
                result["exists"] = True
                result["url"]    = url
        except Exception:
            pass
        return result

    def scan(self, max_names: int = 50) -> list:
        """Run bucket scan across all providers."""
        import concurrent.futures
        names    = self.generate_names()[:max_names]
        findings = []

        print(f"\n[*] Cloud bucket scan: {len(names)} permutations")

        def check_name(name):
            results = []
            for check_fn in [self.check_s3, self.check_azure, self.check_gcp]:
                r = check_fn(name)
                if r["exists"]:
                    results.append(r)
            return results

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            for results in ex.map(check_name, names):
                for r in results:
                    if r["readable"]:
                        print(f"  [!!!] READABLE: [{r['provider'].upper()}] {r['url']}")
                    elif r["exists"]:
                        print(f"  [!] EXISTS (private): [{r['provider'].upper()}] {r['bucket']}")
                    findings.extend([r] if r["exists"] else [])

        return findings


def run_regression_tests():
    print("\n=== ASN MAPPER REGRESSION TESTS ===")
    passed = failed = 0

    mapper = ASNMapper("testphp.vulnweb.com")
    hunter = CloudBucketHunter("acunetix")

    tests = [
        ("ASNMapper instantiates",
         lambda: isinstance(mapper, ASNMapper)),

        ("Domain extracted from URL",
         lambda: ASNMapper("https://testphp.vulnweb.com").domain == "testphp.vulnweb.com"),

        ("BGPView API endpoint correct",
         lambda: "bgpview.io" in ASNMapper.BGPVIEW_API),

        ("_find_asns returns list",
         lambda: isinstance(mapper._find_asns(), list)),

        ("_reverse_ip_lookup returns list",
         lambda: isinstance(mapper._reverse_ip_lookup(), list)),

        ("Masscan command generated after CIDR set",
         lambda: (
             mapper.results["cidrs"].append("192.168.1.0/24") or True,
             len(mapper.get_masscan_command()) > 0
         )[1]),

        ("Naabu command generated",
         lambda: len(mapper.get_naabu_command()) > 0),

        ("CloudBucketHunter instantiates",
         lambda: isinstance(hunter, CloudBucketHunter)),

        ("Name generation produces variations",
         lambda: len(hunter.generate_names()) >= 30),

        ("Name generation includes suffixes",
         lambda: any("backup" in n for n in hunter.generate_names())),

        ("Name generation includes prefixes",
         lambda: any(n.startswith("dev-") for n in hunter.generate_names())),

        ("S3 check returns dict with required keys",
         lambda: all(k in hunter.check_s3("nonexistent-12345xyz")
                    for k in ["exists","readable","url","provider"])),

        ("Azure check returns dict",
         lambda: all(k in hunter.check_azure("nonexistent-12345xyz")
                    for k in ["exists","readable","provider"])),

        ("GCP check returns dict",
         lambda: all(k in hunter.check_gcp("nonexistent-12345xyz")
                    for k in ["exists","readable","provider"])),

        ("S3 check returns dict structure",
         lambda: "exists" in hunter.check_s3("amonstrike-totally-fake-test-9999xwq")),

        ("Name count reasonable",
         lambda: len(hunter.generate_names()) >= 30),

        ("S3 regions populated",
         lambda: len(CloudBucketHunter.S3_REGIONS) >= 8),
    ]

    for name, fn in tests:
        try:
            if fn():
                passed += 1
                print(f"  ✓ {name}")
            else:
                failed += 1
                print(f"  ✗ {name}")
        except Exception as e:
            failed += 1
            print(f"  ✗ {name} — {e}")

    print(f"\n  Passed: {passed}  Failed: {failed}")
    return passed, failed


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        m = ASNMapper(sys.argv[1])
        r = m.run()
        print(json.dumps(r, indent=2))
        h = CloudBucketHunter(sys.argv[1].split(".")[0])
        h.scan(max_names=30)
    else:
        run_regression_tests()
