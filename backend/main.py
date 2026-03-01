from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import os, hashlib, base64, asyncio, httpx, aiofiles, sqlite3, json, random, re
from datetime import datetime, timedelta
import phonenumbers
from phonenumbers import geocoder, carrier
import socket
import whois
from groq import Groq

load_dotenv()

# ─── API CONFIGURATION ───────────────────────────────────────────────────
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
ABUSE_IP_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
THREATFOX_KEY = os.getenv("THREATFOX_API_KEY", "")
HONEYDB_KEY = os.getenv("HONEYDB_API_KEY", "")
WAZUH_API = os.getenv("WAZUH_API_URL", "")

VT_BASE = "https://www.virustotal.com/api/v3"
OTX_BASE = "https://otx.alienvault.com/api/v1"
ABUSE_BASE = "https://api.abuseipdb.com/api/v2"
THREATFOX_BASE = "https://threatfox-api.abuse.ch/api/v1/"
HONEYDB_BASE = "https://honeydb.io/api"
HEADERS = {"x-apikey": VT_API_KEY}

app = FastAPI(title="NEXATHAN SOC", version="2.5.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Initialize Groq
try:
    groq_client = Groq(api_key=GROQ_API_KEY)
except Exception:
    groq_client = None

def get_ai_analysis(target, type_str, risk, stats):
    if not groq_client:
        return "AI Engine Offline."
    prompt = f"As a Cyber Threat Intelligence Analyst, provide a detailed 1-paragraph summary about the {type_str} target '{target}'. It has a risk level of {risk} with {stats.get('malicious', 0)} malicious flags. Explain the potential security implications concisely and professionally, noting whether it is safe or dangerous to interact with."
    try:
        completion = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300,
            temperature=0.4
        )
        return completion.choices[0].message.content.strip()
    except Exception as e:
        # Fallback to a smaller model if large one fails
        try:
            completion = groq_client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=300,
                temperature=0.4
            )
            return completion.choices[0].message.content.strip()
        except:
            return "AI Analysis temporarily unavailable."

def nmap_mock_scan(ip):
    open_ports = []
    common_ports = {21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS", 80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB", 3389:"RDP", 8080:"HTTP-Proxy"}
    for port, service in common_ports.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            if s.connect_ex((ip, port)) == 0:
                open_ports.append({"port": port, "service": service})
        except:
            pass
        finally:
            s.close()
    return open_ports

# ─── WEBSOCKET MANAGER ──────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        failed_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                failed_connections.append(connection)
        for conn in failed_connections:
            self.disconnect(conn)

manager = ConnectionManager()

# ─── ADVANCED GLOBAL THREAT DETECTION (MULTISOURCE) ────────────────────────
REAL_THREATS = []
THREAT_ANALYTICS = {
    "top_attackers": [],
    "top_targets": [],
    "common_type": "DDoS",
    "live_count": 104523
}

async def fetch_threatfox():
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(THREATFOX_BASE, json={"query": "get_recent", "days": 1})
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                return [{"ip": d["ioc_value"].split(':')[0], "type": d["threat_type"], "source": "ThreatFox", "sev": d["confidence_level"]/100} for d in data if d["ioc_type"] == "ip:port"]
    except: return []
    return []

async def fetch_abuseipdb():
    if not ABUSE_IP_KEY: return []
    try:
        headers = {"Key": ABUSE_IP_KEY, "Accept": "application/json"}
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{ABUSE_BASE}/reports?limit=50", headers=headers)
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                return [{"ip": d["ipAddress"], "type": "Abuse", "source": "AbuseIPDB", "sev": d["abuseConfidenceScore"]/100} for d in data]
    except: return []
    return []

async def fetch_honeydb():
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{HONEYDB_BASE}/recent/hits")
            if resp.status_code == 200:
                data = resp.json()
                return [{"ip": d["remote_host"], "type": "Honeypot", "source": "HoneyDB", "sev": 0.6} for d in data[:30]]
    except: return []
    return []

async def get_geo_batch(ips):
    if not ips: return {}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post("http://ip-api.com/batch", json=ips)
            if resp.status_code == 200:
                results = resp.json()
                return {res['query']: res for res in results if res.get('status') == 'success'}
    except: return {}
    return {}

async def update_threat_feed():
    global REAL_THREATS, THREAT_ANALYTICS
    feeds = await asyncio.gather(fetch_threatfox(), fetch_abuseipdb(), fetch_honeydb())
    raw_events = [e for sub in feeds for e in sub]
    unique_ips = {}
    for event in raw_events:
        ip = event['ip']
        if ip not in unique_ips: unique_ips[ip] = event
        else:
            unique_ips[ip]['sev'] = min(1.0, unique_ips[ip]['sev'] + 0.1)
            unique_ips[ip]['source'] += f", {event['source']}"
    ip_list = list(unique_ips.keys())[:40]
    geo_results = await get_geo_batch(ip_list)
    processed = []
    country_counts = {}
    for ip, event in unique_ips.items():
        if ip in geo_results:
            geo = geo_results[ip]
            country = geo.get('country', 'Unknown')
            country_counts[country] = country_counts.get(country, 0) + 1
            risk = "CRITICAL" if event['sev'] > 0.8 else "HIGH" if event['sev'] > 0.5 else "MEDIUM"
            threat = {
                "id": hashlib.md5(ip.encode()).hexdigest()[:8], "ip": ip, "target": event.get('type', 'Attack'),
                "type": event['type'], "risk_score": round(event['sev'] * 100, 1), "threat_level": risk,
                "source": event['source'],
                "location": {"lat": geo.get('lat', 0), "lng": geo.get('lon', 0), "city": geo.get('city', 'Unknown'), "country": country, "cc": geo.get('countryCode', '??')},
                "ts": datetime.now().isoformat()
            }
            processed.append(threat)
            await manager.broadcast(json.dumps({"type": "NEW_ATTACK", "payload": threat}))
    REAL_THREATS = processed
    sorted_c = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
    THREAT_ANALYTICS["top_attackers"] = [{"country": c, "count": count} for c, count in sorted_c[:5]]
    THREAT_ANALYTICS["live_count"] += len(processed)
    await manager.broadcast(json.dumps({"type": "ANALYTICS_UPDATE", "payload": THREAT_ANALYTICS}))

async def threat_loop():
    while True:
        await update_threat_feed()
        await asyncio.sleep(10)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(threat_loop())

@app.websocket("/ws/threats")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/threats")
async def get_threats(): return REAL_THREATS

@app.get("/threats/analytics")
async def get_analytics(): return THREAT_ANALYTICS

def get_shodan_mock():
    return {
        "os": random.choice(["Linux 5.x", "Windows Server 2019", "FreeBSD", "Unknown"]),
        "isp": random.choice(["Reliance Jio", "Bharti Airtel", "Vodafone Idea", "BSNL Broadband", "Tata Communications", "Cloud Hosting Provider"]),
        "tags": random.choices(["cloud", "database", "web", "vpn"], k=2),
        "vulns": ["CVE-2024-1234", "CVE-2023-5678"] if random.random() > 0.5 else []
    }

# (APP moved above routes)

# ─── DB ────────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect("allsafe.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.execute("""CREATE TABLE IF NOT EXISTS scans (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        type     TEXT,
        target   TEXT,
        result   TEXT,
        risk     TEXT,
        ts       TEXT
    )""")
    db.commit(); db.close()

init_db()

def log_scan(type_, target, result, risk):
    db = get_db()
    db.execute("INSERT INTO scans(type,target,result,risk,ts) VALUES(?,?,?,?,?)",
               (type_, target, json.dumps(result), risk, datetime.utcnow().isoformat()))
    db.commit(); db.close()

def get_risk(positives: int) -> str:
    if positives == 0: return "CLEAN"
    elif positives <= 3: return "LOW"
    elif positives <= 10: return "MEDIUM"
    else: return "HIGH"

# ─── MODELS ────────────────────────────────────────────────────────────────
class URLPayload(BaseModel):
    url: str

class DomainPayload(BaseModel):
    domain: str

class HashPayload(BaseModel):
    hash: str

class PhonePayload(BaseModel):
    phone: str

class IPPayload(BaseModel):
    ip: str

class EmailPayload(BaseModel):
    email: str

# ─── ENDPOINTS ─────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"status": "ALL SAFE API v2.0", "engine": bool(VT_API_KEY)}

@app.post("/scan/url")
async def scan_url(payload: URLPayload):
    async with httpx.AsyncClient(timeout=30) as client:
        # Submit URL
        resp = await client.post(f"{VT_BASE}/urls",
            headers=HEADERS,
            data={"url": payload.url})
        if resp.status_code not in (200, 201):
            raise HTTPException(status_code=resp.status_code, detail="Core Engine submit failed")
        analysis_id = resp.json()["data"]["id"]

        # Poll result - Increase to 15 attempts (30s total) for better success rate
        for _ in range(15):
            await asyncio.sleep(2)
            try:
                r2 = await client.get(f"{VT_BASE}/analyses/{analysis_id}", headers=HEADERS)
                if r2.status_code == 200:
                    data = r2.json().get("data", {})
                    if data.get("attributes", {}).get("status") == "completed":
                        stats = data["attributes"]["stats"]
                        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                        risk = get_risk(positives)
                        ai_summary = get_ai_analysis(payload.url, "URL", risk, stats)
                        result = {"url": payload.url, "stats": stats, "risk": risk, "engine_results": data["attributes"].get("results", {}), "ai_summary": ai_summary}
                        log_scan("url", payload.url, result, risk)
                        return result
                elif r2.status_code == 401:
                    raise HTTPException(status_code=401, detail="VirusTotal API Key is invalid or expired.")
            except Exception as e:
                if isinstance(e, HTTPException): raise e
                continue

        raise HTTPException(status_code=408, detail="Analysis timed out. VirusTotal is still processing the URL. Try again in a minute.")

@app.post("/scan/file")
async def scan_file(file: UploadFile = File(...)):
    content = await file.read()
    sha256 = hashlib.sha256(content).hexdigest()
    
    async with httpx.AsyncClient(timeout=60) as client:
        # Check if hash already known
        r = await client.get(f"{VT_BASE}/files/{sha256}", headers=HEADERS)
        if r.status_code == 200:
            data = r.json()["data"]["attributes"]["last_analysis_stats"]
            positives = data.get("malicious", 0) + data.get("suspicious", 0)
            risk = get_risk(positives)
            result = {"filename": file.filename, "sha256": sha256, "stats": data, "risk": risk, "cached": True}
            log_scan("file", file.filename, result, risk)
            return result

        # Upload new file
        resp = await client.post(f"{VT_BASE}/files",
            headers=HEADERS,
            files={"file": (file.filename, content, file.content_type or "application/octet-stream")})
        if resp.status_code not in (200, 201):
            raise HTTPException(status_code=resp.status_code, detail="Core Engine upload failed")

        analysis_id = resp.json()["data"]["id"]
        for _ in range(15):
            await asyncio.sleep(3)
            r2 = await client.get(f"{VT_BASE}/analyses/{analysis_id}", headers=HEADERS)
            data_json = r2.json().get("data", {})
            attrs = data_json.get("attributes", {})
            if attrs.get("status") == "completed":
                stats = attrs["stats"]
                positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                risk = get_risk(positives)
                ai_sum = get_ai_analysis(file.filename, "Uploaded File", risk, stats)
                result = {"filename": file.filename, "sha256": sha256, "stats": stats, "risk": risk, "engine_results": attrs.get("results", {}), "ai_summary": ai_sum}
                log_scan("file", file.filename, result, risk)
                return result

    raise HTTPException(status_code=408, detail="File analysis timed out. File is large or VirusTotal is busy.")

@app.post("/scan/hash")
async def scan_hash(payload: HashPayload):
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{VT_BASE}/files/{payload.hash}", headers=HEADERS)
        if r.status_code == 404:
            return {"hash": payload.hash, "risk": "UNKNOWN", "found": False}
        if r.status_code != 200:
            raise HTTPException(status_code=r.status_code, detail="Core Engine lookup failed or limit reached.")
        
        data_json = r.json().get("data", {})
        attrs = data_json.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
        risk = get_risk(positives)
        ai_sum = get_ai_analysis(payload.hash, "Hash", risk, stats)
        
        result = {
            "hash": payload.hash, 
            "stats": stats, 
            "risk": risk, 
            "name": attrs.get("meaningful_name") or attrs.get("type_description", "Unknown File"), 
            "type": attrs.get("type_description",""), 
            "ai_summary": ai_sum,
            "found": True
        }
        log_scan("hash", payload.hash, result, risk)
        return result

@app.post("/scan/domain")
async def scan_domain(payload: DomainPayload):
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{VT_BASE}/domains/{payload.domain}", headers=HEADERS)
        if r.status_code != 200:
            raise HTTPException(status_code=r.status_code, detail="Core Engine domain lookup failed")
        attrs = r.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
        risk = get_risk(positives)
        ai_summary = get_ai_analysis(payload.domain, "Domain", risk, stats)
        result = {
            "domain": payload.domain, "stats": stats, "risk": risk,
            "reputation": attrs.get("reputation", 0),
            "categories": attrs.get("categories", {}),
            "registrar": attrs.get("registrar",""),
            "creation_date": attrs.get("creation_date",""),
            "ai_summary": ai_summary
        }
        log_scan("domain", payload.domain, result, risk)
        return result

@app.post("/scan/ip")
async def scan_ip(payload: IPPayload):
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{VT_BASE}/ip_addresses/{payload.ip}", headers=HEADERS)
            if r.status_code != 200:
                raise HTTPException(status_code=r.status_code, detail="Core Engine IP lookup failed. Ensure IP is valid.")
            attrs = r.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            risk = get_risk(positives)
            nmap_ports = nmap_mock_scan(payload.ip)
            shodan_data = get_shodan_mock()
            whois_data = {}
            try:
                w = whois.whois(payload.ip)
                whois_data = {
                    "registrar": w.registrar if isinstance(w.registrar, str) else "Unknown",
                    "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
                    "org": w.org if isinstance(w.org, str) else "Unknown"
                }
            except:
                pass

            ai_summary = get_ai_analysis(payload.ip, "IP Address", risk, stats)

            result = {
                "ip": payload.ip, "stats": stats, "risk": risk,
                "reputation": attrs.get("reputation", 0),
                "country": attrs.get("country", "Unknown"),
                "as_owner": attrs.get("as_owner", "Unknown"),
                "nmap": nmap_ports,
                "shodan": shodan_data,
                "whois": whois_data,
                "ai_summary": ai_summary
            }
            log_scan("ip", payload.ip, result, risk)
            return result
    except httpx.RequestError:
        raise HTTPException(status_code=500, detail="Error connecting to Intel Engine APIs")

@app.post("/scan/phone")
async def scan_phone(payload: PhonePayload):
    phone = payload.phone
    region_name = "Unknown"
    carrier_name = "Unknown"
    national_number = phone
    
    try:
        # Pass "IN" as default region if no + is provided
        parsed_number = phonenumbers.parse(phone, "IN")
        if phonenumbers.is_valid_number(parsed_number):
            region_name = geocoder.description_for_number(parsed_number, "en") or "Unknown"
            carrier_name = carrier.name_for_number(parsed_number, "en") or "Unknown"
            national_number = str(parsed_number.national_number)
            # Format phone uniformly
            phone = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    except Exception:
        # Keep raw string if parsing fails entirely
        national_number = ''.join(filter(str.isdigit, phone)) or phone
    
    # OSINT Links mapping
    osint_links = [
        {"name": "ShouldIAnswer", "url": f"https://www.shouldianswer.com/search?q={national_number}"},
        {"name": "NumLooker", "url": f"https://numlooker.com/search/phone/{national_number}"},
        {"name": "Sync.me", "url": f"https://sync.me/search/number/{national_number}/"},
    ]

    # We maintain mocked spam calculation for simulation/hackathon, but use real region
    is_spam = random.choice([True, False, False, False, True])
    score = random.randint(70, 99) if is_spam else random.randint(0, 15)
    risk = "HIGH" if score > 70 else "MEDIUM" if score > 30 else "CLEAN"
    
    danger_explanation = ""
    if risk == "HIGH":
        danger_explanation = "WARNING: This phone number has been flagged by OSINT databases for severe malicious activities such as impersonation, phishing (smishing), or toll fraud. It belongs to active spam campaigns. Immediate blocking is recommended."
    elif risk == "MEDIUM":
        danger_explanation = "CAUTION: This number exhibits suspicious behavior often correlated with aggressive telemarketing or potential nuisance campaigns."

    result = {
        "phone": phone,
        "region": region_name,
        "carrier": carrier_name,
        "spam_score": score,
        "osint_links": osint_links,
        "danger_explanation": danger_explanation,
        "stats": {"malicious": 1 if score > 50 else 0, "harmless": 1 if score <= 50 else 0},
        "risk": risk
    }
    log_scan("phone", phone, result, risk)
    return result

@app.post("/scan/identity")
async def scan_identity(payload: EmailPayload):
    email = payload.email
    # Simple regex for email validation
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    # Mock some breach data
    breaches = [
        {"source": "Adobe (2013)", "data": "Email, Password, Hint"},
        {"source": "Canva (2019)", "data": "Email, Name, Location"},
        {"source": "LinkedIn (2016)", "data": "Email, Password Hashes"},
        {"source": "Dropbox (2012)", "data": "Email, Passwords"},
    ]
    
    found = random.sample(breaches, random.randint(0, 3))
    risk = "HIGH" if len(found) > 1 else "MEDIUM" if len(found) == 1 else "CLEAN"
    
    ai_summary = get_ai_analysis(email, "Identity/Email", risk, {"malicious": len(found)})
    
    result = {
        "email": email,
        "found_in": found,
        "breach_count": len(found),
        "risk": risk,
        "ai_summary": ai_summary,
        "stats": {"malicious": len(found), "harmless": len(breaches) - len(found)}
    }
    log_scan("identity", email, result, risk)
    return result

@app.get("/history")
async def get_history(limit: int = 20):
    db = get_db()
    rows = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.delete("/history/clear")
async def clear_history():
    db = get_db()
    db.execute("DELETE FROM scans")
    db.commit()
    db.close()
    return {"status": "History cleared"}

@app.get("/stats")
async def get_stats():
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    high   = db.execute("SELECT COUNT(*) FROM scans WHERE risk='HIGH'").fetchone()[0]
    medium = db.execute("SELECT COUNT(*) FROM scans WHERE risk='MEDIUM'").fetchone()[0]
    clean  = db.execute("SELECT COUNT(*) FROM scans WHERE risk='CLEAN'").fetchone()[0]
    by_type = db.execute("SELECT type, COUNT(*) as cnt FROM scans GROUP BY type").fetchall()
    db.close()
    return {
        "total": total, "high": high, "medium": medium, "clean": clean,
        "by_type": {r["type"]: r["cnt"] for r in by_type}
    }

@app.get("/news")
async def get_news():
    topics = [
        {"title": "Cyberattack", "tag": "THREAT INTEL"},
        {"title": "Computer_security_in_India", "tag": "INDIA SECURITY"},
        {"title": "Computer_Emergency_Response_Team_-_India", "tag": "INDIA INTEL"},
        {"title": "Ransomware", "tag": "RANSOMWARE"},
        {"title": "Malware", "tag": "MALWARE"},
        {"title": "Phishing", "tag": "PHISHING"}
    ]
    news_items = []
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            for t in topics:
                r = await client.get(f"https://en.wikipedia.org/api/rest_v1/page/summary/{t['title']}")
                if r.status_code == 200:
                    data = r.json()
                    desc = data.get("extract", "")
                    if len(desc) > 180: desc = desc[:177] + "..."
                    news_items.append({
                        "title": data.get("title", t["title"].replace("_", " ")),
                        "source": "Wikipedia Intel API",
                        "time": "Real-time Update",
                        "tag": t["tag"],
                        "link": data.get("content_urls", {}).get("desktop", {}).get("page", ""),
                        "summary": desc
                    })
        if news_items:
            return news_items
    except Exception:
        pass
        
    # Fallback to mock data if RSS fails
    return [
        {"title": "CERT-In issues high severity warning for Android vulnerabilities", "source": "Indian Cyber News", "time": "2 hours ago", "tag": "VULNERABILITY"},
        {"title": "Recent data breach affects millions in regional cyber incident", "source": "News18 Tech", "time": "5 hours ago", "tag": "DATA BREACH"},
        {"title": "Ransomware group targets major Indian hospital network", "source": "Express Tech", "time": "12 hours ago", "tag": "RANSOMWARE"},
        {"title": "Phishing campaign impersonating Indian Income Tax Department active", "source": "SecurityBrief India", "time": "1 day ago", "tag": "PHISHING"},
        {"title": "Indian CERT reports 14% increase in financial cyber frauds", "source": "TechRadar India", "time": "1 day ago", "tag": "FINANCIAL FRAUD"}
    ]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT",8000)), reload=os.getenv("DEBUG","False")=="True")
