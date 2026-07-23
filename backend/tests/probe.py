import httpx, jwt, os, uuid
from datetime import datetime, timedelta
BASE = "https://localhost:8000"
SECRET = os.environ["JWT_SECRET"]

def mint(u, r, i, uid):
    return jwt.encode({"sub":u,"role":r,"initials":i,"id":uid,"exp":datetime.utcnow()+timedelta(minutes=30)},SECRET,algorithm="HS256")

c = httpx.Client(base_url=BASE, verify=False, timeout=15)
auth = {"Authorization": "Bearer " + mint("admin","admin","ADM",1)}

cname = "_probe_" + uuid.uuid4().hex[:6]
r = c.post("/api/mitre/cases", json={"name":cname,"lead":"TST"}, headers=auth)
print("case_create", r.status_code, r.text[:300])
if r.status_code == 200:
    data = r.json()
    print("  case_create_body:", data)
    c.delete(f"/api/mitre/cases/{cname}", headers=auth)

r2 = c.get("/api/mitre/audit", headers=auth)
print("audit", r2.status_code, r2.text[:300])

r3 = c.post("/api/profiles", json={"name":"_probe_profile","t_codes":["T1059"]}, headers=auth)
print("profile_create", r3.status_code, r3.text[:300])
if r3.status_code == 200:
    pid = r3.json().get("id") or r3.json().get("profile_id")
    print("  profile_id field:", list(r3.json().keys()))
    if pid:
        c.delete(f"/api/profiles/{pid}", headers=auth)

r4 = c.delete("/api/mitre/cases/_no_such_case_xyz", headers=auth)
print("del_nonexistent", r4.status_code, r4.text[:100])

try:
    r5 = c.get("/api/ioc/search", params={"query":"test"}, headers=auth, timeout=8)
    print("ioc_search", r5.status_code, r5.text[:200])
except Exception as e:
    print("ioc_search_err", type(e).__name__, str(e)[:150])

cname2 = "_probe2_" + uuid.uuid4().hex[:6]
r6 = c.post("/api/mitre/cases", json={"name":cname2,"lead":"TST"}, headers=auth)
if r6.status_code == 200:
    r7 = c.post(f"/api/mitre/cases/{cname2}/assets",
                json={"hostname":"_test","ip_address":"127.0.0.1"}, headers=auth)
    print("asset_create", r7.status_code, r7.text[:300])
    if r7.status_code == 200:
        aid = r7.json().get("asset_id") or r7.json().get("id")
        print("  asset_id field:", list(r7.json().keys()), "value:", aid)
    c.delete(f"/api/mitre/cases/{cname2}", headers=auth)
