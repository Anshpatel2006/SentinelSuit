import base64
import io
import ipaddress
import math
import os
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent
DATASET_NAME = "phishing link detection dataset.csv"
DATASET_PATH = BASE_DIR / DATASET_NAME

FEATURES = [
    "url_length",
    "has_ip_address",
    "dot_count",
    "https_flag",
    "url_entropy",
    "token_count",
    "subdomain_count",
    "query_param_count",
    "tld_length",
    "path_length",
    "has_hyphen_in_domain",
    "number_of_digits",
    "tld_popularity",
    "suspicious_file_extension",
    "domain_name_length",
    "percentage_numeric_chars",
]

POPULAR_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "in", "co",
    "uk", "de", "fr", "au", "ca", "jp", "us", "io", "ai",
    "app", "dev", "info", "biz", "me"
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs",
    ".js", ".jar", ".msi", ".zip", ".rar", ".apk"
}

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "verification", "account",
    "update", "secure", "security", "password", "credential",
    "bank", "wallet", "payment", "invoice", "confirm",
    "authentication", "unlock", "suspended", "urgent",
    "bonus", "free", "gift", "claim", "recover"
]

app = FastAPI(title="Phishing Link Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def normalize_url(url):
    url = str(url).strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        url = "https://" + url
    return url


def validate_url(url):
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False, "Only HTTP and HTTPS URLs are supported."
        if not p.hostname:
            return False, "A valid hostname was not found."
        return True, "Valid URL"
    except Exception:
        return False, "Invalid URL format."


def entropy(text):
    if not text:
        return 0.0
    counts = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    n = len(text)
    return float(-sum((v / n) * math.log2(v / n) for v in counts.values()))


def is_ip(host):
    try:
        ipaddress.ip_address(host or "")
        return 1
    except Exception:
        return 0


def get_tld(host):
    parts = (host or "").lower().strip(".").split(".")
    return parts[-1] if len(parts) >= 2 else ""


def subdomain_count(host):
    host = (host or "").lower().strip(".")
    if not host or is_ip(host):
        return 0
    return max(0, len(host.split(".")) - 2)


def extract_features(url):
    p = urlparse(url)
    host = p.hostname or ""
    host_no_www = host[4:] if host.startswith("www.") else host
    tld = get_tld(host)
    tokens = [x for x in re.split(r"[/\-_\.?=&:%@#]+", url) if x]
    digits = sum(c.isdigit() for c in url)

    row = {
        "url_length": len(url),
        "has_ip_address": is_ip(host),
        "dot_count": url.count("."),
        "https_flag": int(p.scheme.lower() == "https"),
        "url_entropy": entropy(url),
        "token_count": len(tokens),
        "subdomain_count": subdomain_count(host),
        "query_param_count": len(parse_qs(p.query, keep_blank_values=True)),
        "tld_length": len(tld),
        "path_length": len(p.path or ""),
        "has_hyphen_in_domain": int("-" in host),
        "number_of_digits": digits,
        "tld_popularity": int(tld in POPULAR_TLDS),
        "suspicious_file_extension": int(any(ext in url.lower() for ext in SUSPICIOUS_EXTENSIONS)),
        "domain_name_length": len(host_no_www),
        "percentage_numeric_chars": (digits / len(url) * 100) if url else 0,
    }
    return pd.DataFrame([row])[FEATURES]


def prepare_dataset(path):
    df = pd.read_csv(path)

    if "ClassLabel" not in df.columns:
        raise ValueError("Dataset must contain a 'ClassLabel' column.")

    df = df.copy()
    df["ClassLabel"] = pd.to_numeric(df["ClassLabel"], errors="coerce")
    df = df.dropna(subset=["ClassLabel"])

    if all(c in df.columns for c in FEATURES):
        X = df[FEATURES].copy()
    elif "URL" in df.columns:
        X = pd.concat(
            [extract_features(normalize_url(u)) for u in df["URL"].fillna("")],
            ignore_index=True,
        )
    else:
        raise ValueError("Dataset must contain either all engineered feature columns or a URL column.")

    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    # Supplied notebook convention:
    # 0 = phishing, 1 = legitimate.
    # Internal target: 1 = phishing, 0 = legitimate.
    y = (df["ClassLabel"].astype(int) == 0).astype(int)

    return X, y, df


_model = None
_metrics = None


class HeuristicModel:
    """Allow local scans when the optional training dataset is unavailable."""

    def predict_proba(self, features):
        scores = (
            features["has_ip_address"] * 0.25
            + (1 - features["https_flag"]) * 0.15
            + (features["url_length"] > 100).astype(float) * 0.10
            + (features["subdomain_count"] >= 3).astype(float) * 0.10
            + features["has_hyphen_in_domain"] * 0.05
            + (features["number_of_digits"] >= 5).astype(float) * 0.10
            + features["suspicious_file_extension"] * 0.10
            + (features["domain_name_length"] > 30).astype(float) * 0.05
            + (features["percentage_numeric_chars"] > 20).astype(float) * 0.10
        ).clip(0, 1)
        return np.column_stack([1 - scores, scores])

    def predict(self, features):
        return (self.predict_proba(features)[:, 1] >= 0.5).astype(int)


def train_model():
    global _model, _metrics

    if not DATASET_PATH.exists():
        _model = HeuristicModel()
        _metrics = {
            "accuracy": 0,
            "precision": 0,
            "recall": 0,
            "f1": 0,
            "roc_auc": 0,
            "rows": 0,
            "train_rows": 0,
            "test_rows": 0,
            "fallback": True,
        }
        return

    X, y, df = prepare_dataset(DATASET_PATH)

    if y.nunique() < 2:
        raise ValueError("The dataset must contain both phishing and legitimate samples.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    pred = model.predict(X_test)
    prob = model.predict_proba(X_test)[:, 1]

    _model = model
    _metrics = {
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision": float(precision_score(y_test, pred, zero_division=0)),
        "recall": float(recall_score(y_test, pred, zero_division=0)),
        "f1": float(f1_score(y_test, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, prob)),
        "rows": int(len(df)),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
    }


def ensure_model():
    if _model is None:
        train_model()


def rule_analysis(url):
    p = urlparse(url)
    host = p.hostname or ""
    low = url.lower()
    indicators = []
    score = 0

    if is_ip(host):
        indicators.append("The URL uses an IP address instead of a domain.")
        score += 20
    if p.scheme.lower() != "https":
        indicators.append("The URL does not use HTTPS.")
        score += 10
    if len(url) > 100:
        indicators.append("The URL is unusually long.")
        score += 10
    if subdomain_count(host) >= 3:
        indicators.append("The URL contains multiple subdomains.")
        score += 10
    if "-" in host:
        indicators.append("The domain contains a hyphen.")
        score += 5

    digits = sum(c.isdigit() for c in url)
    if digits >= 5:
        indicators.append("The URL contains many numeric characters.")
        score += 10
    if any(ext in low for ext in SUSPICIOUS_EXTENSIONS):
        indicators.append("A potentially suspicious file extension was found.")
        score += 15

    words = [w for w in SUSPICIOUS_WORDS if w in low]
    if words:
        indicators.append("Suspicious keywords: " + ", ".join(words[:8]))
        score += min(20, len(words) * 4)

    if "@" in url:
        indicators.append("The URL contains an @ character.")
        score += 20

    return {"score": min(score, 100), "indicators": indicators, "keywords": words}


def website_analysis(url):
    result = {
        "accessible": False,
        "status_code": None,
        "title": "",
        "forms": 0,
        "password_inputs": 0,
        "external_links": 0,
        "score": 0,
        "indicators": [],
    }

    try:
        response = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 PhishingLinkDetector/1.0"},
            timeout=8,
            allow_redirects=True,
        )
        result["accessible"] = True
        result["status_code"] = response.status_code

        soup = BeautifulSoup(response.text[:2_000_000], "html.parser")

        if soup.title:
            result["title"] = soup.title.get_text(strip=True)[:200]

        forms = soup.find_all("form")
        passwords = soup.find_all(
            "input", attrs={"type": re.compile("^password$", re.I)}
        )
        result["forms"] = len(forms)
        result["password_inputs"] = len(passwords)

        base_host = urlparse(url).hostname
        external = 0
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("http"):
                h = urlparse(href).hostname
                if h and base_host and h != base_host:
                    external += 1
        result["external_links"] = external

        page_text = soup.get_text(" ", strip=True).lower()
        found = [w for w in SUSPICIOUS_WORDS if w in page_text]

        if result["password_inputs"] > 0:
            result["indicators"].append("Password input fields detected.")
            result["score"] += 10
        if result["forms"] > 2:
            result["indicators"].append("Multiple forms detected.")
            result["score"] += 10
        if len(found) >= 4:
            result["indicators"].append(
                "Several suspicious/security keywords detected in page content."
            )
            result["score"] += 15

        result["score"] = min(result["score"], 40)

    except requests.exceptions.Timeout:
        result["indicators"].append("Website request timed out.")
        result["score"] = 5
    except requests.exceptions.RequestException:
        result["indicators"].append("Website could not be accessed.")
        result["score"] = 5
    except Exception:
        result["indicators"].append("Website content analysis failed.")
        result["score"] = 5

    return result


def virustotal(url, api_key):
    result = {"available": False, "malicious": 0, "suspicious": 0, "score": 0}
    if not api_key:
        return result

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
        if r.status_code == 200:
            stats = (
                r.json().get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            result["available"] = True
            result["malicious"] = int(stats.get("malicious", 0))
            result["suspicious"] = int(stats.get("suspicious", 0))
            if result["malicious"] > 0:
                result["score"] = 40
            elif result["suspicious"] > 0:
                result["score"] = 25
    except Exception:
        pass

    return result


def safe_browsing(url, api_key):
    result = {"available": False, "threats": [], "score": 0}
    if not api_key:
        return result

    try:
        r = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": api_key},
            json={
                "client": {
                    "clientId": "phishing-link-detector",
                    "clientVersion": "1.0",
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
            timeout=10,
        )
        if r.status_code == 200:
            result["available"] = True
            result["threats"] = [
                x.get("threatType", "Unknown")
                for x in r.json().get("matches", [])
            ]
            if result["threats"]:
                result["score"] = 40
    except Exception:
        pass

    return result


def risk_assessment(probability, rules, website, vt, safe):
    ml_score = probability * 100
    threat_score = min(vt["score"] + safe["score"], 100)

    final = (
        ml_score * 0.50
        + rules["score"] * 0.25
        + website["score"] * 0.10
        + threat_score * 0.15
    )
    final = round(min(max(final, 0), 100), 2)

    if final >= 80:
        category = "Very High Risk"
    elif final >= 60:
        category = "High Risk"
    elif final >= 40:
        category = "Medium Risk"
    else:
        category = "Low Risk"

    return final, category, {
        "ml": round(ml_score, 2),
        "rules": rules["score"],
        "website": website["score"],
        "threat_intelligence": threat_score,
    }


class ScanRequest(BaseModel):
    url: str
    virustotal_api_key: str = ""
    google_safe_browsing_api_key: str = ""


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/model-info")
def model_info():
    try:
        ensure_model()
        return _metrics
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/scan")
def scan(request: ScanRequest):
    try:
        ensure_model()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Model initialization failed: {exc}")

    url = normalize_url(request.url)
    valid, message = validate_url(url)
    if not valid:
        raise HTTPException(status_code=400, detail=message)

    features = extract_features(url)
    pred = int(_model.predict(features)[0])
    probability = float(_model.predict_proba(features)[0, 1])

    ml_label = "Phishing" if pred == 1 else "Legitimate"
    rules = rule_analysis(url)
    website = website_analysis(url)
    vt = virustotal(url, request.virustotal_api_key)
    safe = safe_browsing(url, request.google_safe_browsing_api_key)

    risk_score, risk_category, component_scores = risk_assessment(
        probability, rules, website, vt, safe
    )

    indicators = []
    indicators.extend(rules["indicators"])
    indicators.extend(website["indicators"])

    if vt["malicious"] > 0:
        indicators.append(
            f"VirusTotal reported {vt['malicious']} malicious detection(s)."
        )
    if vt["suspicious"] > 0:
        indicators.append(
            f"VirusTotal reported {vt['suspicious']} suspicious detection(s)."
        )
    if safe["threats"]:
        indicators.append(
            "Google Safe Browsing threats: " + ", ".join(safe["threats"])
        )

    indicators = list(dict.fromkeys(indicators))

    return {
        "url": url,
        "features": {k: float(v) if isinstance(v, (np.floating, float)) else int(v) for k, v in features.iloc[0].to_dict().items()},
        "ml_label": ml_label,
        "ml_probability": probability * 100,
        "risk_score": risk_score,
        "risk_category": risk_category,
        "component_scores": component_scores,
        "rules": rules,
        "website": website,
        "virustotal": vt,
        "safe_browsing": safe,
        "threat_indicators": [
            *([f"VirusTotal malicious detections: {vt['malicious']}"] if vt["malicious"] else []),
            *([f"VirusTotal suspicious detections: {vt['suspicious']}"] if vt["suspicious"] else []),
            *([f"Google Safe Browsing: {', '.join(safe['threats'])}"] if safe["threats"] else []),
        ],
        "indicators": indicators,
    }


@app.post("/api/report")
def report(result: dict):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, rightMargin=35, leftMargin=35, topMargin=35, bottomMargin=35
    )
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Phishing Link Detection Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"<b>URL:</b> {result.get('url', '')}", styles["BodyText"]),
        Paragraph(f"<b>ML Prediction:</b> {result.get('ml_label', '')}", styles["BodyText"]),
        Paragraph(f"<b>Phishing Probability:</b> {float(result.get('ml_probability', 0)):.2f}%", styles["BodyText"]),
        Paragraph(f"<b>Risk Score:</b> {float(result.get('risk_score', 0)):.2f}/100", styles["BodyText"]),
        Paragraph(f"<b>Risk Category:</b> {result.get('risk_category', '')}", styles["BodyText"]),
        Spacer(1, 15),
        Paragraph("Security Indicators", styles["Heading2"]),
    ]

    indicators = result.get("indicators", [])
    data = [["#", "Indicator"]]
    if indicators:
        data.extend([[str(i), item] for i, item in enumerate(indicators, 1)])
    else:
        data.append(["-", "No significant indicators detected."])

    table = Table(data, colWidths=[35, 480])
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )
    story.extend([table, Spacer(1, 15), Paragraph("Extracted URL Features", styles["Heading2"])])

    feature_data = [["Feature", "Value"]]
    for feature, value in result.get("features", {}).items():
        feature_data.append([feature, str(value)])

    feature_table = Table(feature_data, colWidths=[260, 255])
    feature_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ])
    )
    story.append(feature_table)

    doc.build(story)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=phishing_detection_report.pdf"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
