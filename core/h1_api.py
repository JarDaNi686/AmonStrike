"""AmonStrike — HackerOne Draft API. Creates draft reports automatically."""
import requests

class H1DraftAPI:
    BASE = "https://api.hackerone.com/v1"

    def __init__(self, username: str, token: str, program_handle: str):
        self.auth    = (username, token)
        self.handle  = program_handle

    def create_draft(self, submission: dict) -> dict:
        """Create a draft report on HackerOne."""
        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "title":                     submission.get("title",""),
                    "vulnerability_information": submission.get("vulnerability_information",""),
                    "impact":                    submission.get("impact",""),
                    "severity_rating":           submission.get("severity","medium"),
                    "weakness_id":               submission.get("weakness_id"),
                }
            }
        }
        try:
            r = requests.post(
                f"{self.BASE}/hackers/reports",
                auth=self.auth,
                json=payload,
                headers={"Accept":"application/json"},
                timeout=15,
            )
            if r.status_code in [200,201]:
                data = r.json().get("data",{})
                return {
                    "success": True,
                    "report_id": data.get("id",""),
                    "url": f"https://hackerone.com/reports/{data.get('id','')}",
                }
            return {"success":False,"error":r.text[:200]}
        except Exception as e:
            return {"success":False,"error":str(e)}
