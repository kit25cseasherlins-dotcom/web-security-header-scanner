"""
Automated Web Security Scanner  (v2)
------------------------------------
Audits websites for security header gaps, CORS flaws, HTTPS problems,
insecure cookies and information disclosure. Every finding is explained as
THREAT -> VULNERABILITY -> RISK -> MITIGATION and mapped to OWASP Top 10.

Built for the IBM SkillsBuild National Cybersecurity Bootcamp (Oct 2026).

Usage:
    python scanner.py https://example.com
    python scanner.py -f urls.txt
    python scanner.py -f urls.txt -o report

ETHICAL USE: scan only websites you own or have permission to test.
This tool only reads normal responses (passive checks). No attacks are performed.
"""

import argparse
import csv
import html
import sys
from datetime import datetime
from urllib.parse import urlparse

import requests

TEST_ORIGIN = "https://evil-test-origin.example"
WEIGHT = {"High": 3, "Medium": 2, "Low": 1}

# ---------------------------------------------------------------
# 1. Knowledge base: what each security header protects against
# ---------------------------------------------------------------
SECURITY_HEADERS = {
    "Strict-Transport-Security": dict(
        severity="High",
        threat="Man-in-the-Middle / SSL stripping",
        owasp="A02:2021 Cryptographic Failures",
        fix="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    "Content-Security-Policy": dict(
        severity="High",
        threat="Cross-Site Scripting (XSS) / data injection",
        owasp="A03:2021 Injection",
        fix="Add: Content-Security-Policy: default-src 'self'",
    ),
    "X-Frame-Options": dict(
        severity="Medium",
        threat="Clickjacking (page hidden inside another site)",
        owasp="A05:2021 Security Misconfiguration",
        fix="Add: X-Frame-Options: DENY (or SAMEORIGIN)",
    ),
    "X-Content-Type-Options": dict(
        severity="Medium",
        threat="MIME-type sniffing attacks",
        owasp="A05:2021 Security Misconfiguration",
        fix="Add: X-Content-Type-Options: nosniff",
    ),
    "Referrer-Policy": dict(
        severity="Low",
        threat="Leaking private URL info to other sites",
        owasp="A05:2021 Security Misconfiguration",
        fix="Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    "Permissions-Policy": dict(
        severity="Low",
        threat="Abuse of browser features (camera, mic, location)",
        owasp="A05:2021 Security Misconfiguration",
        fix="Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ),
}


def finding(check, passed, severity, threat, owasp, evidence, fix):
    """One scan result row (a 'vulnerability' if not passed)."""
    return {
        "check": check, "passed": passed, "severity": severity,
        "threat": threat, "owasp": owasp, "evidence": evidence,
        "fix": "OK" if passed else fix,
    }


# ---------------------------------------------------------------
# 2. Fetch the site (with a fake Origin so we can test CORS)
# ---------------------------------------------------------------
def fetch(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    resp = requests.get(
        url,
        headers={"Origin": TEST_ORIGIN, "User-Agent": "WebSecurityScanner/2.0"},
        timeout=10,
        allow_redirects=True,
    )
    return resp.url, resp


# ---------------------------------------------------------------
# 3. The checks
# ---------------------------------------------------------------
def check_headers(resp):
    out = []
    for name, info in SECURITY_HEADERS.items():
        value = resp.headers.get(name)
        out.append(finding(
            f"Header: {name}", value is not None, info["severity"],
            info["threat"], info["owasp"],
            value if value else "Header not present", info["fix"],
        ))
    return out


def check_https(final_url):
    ok = final_url.startswith("https://")
    return finding(
        "HTTPS in use", ok, "High",
        "Eavesdropping / data theft on the network",
        "A02:2021 Cryptographic Failures",
        "Site served over HTTPS" if ok else "Site served over plain HTTP",
        "Install a TLS certificate (free via Let's Encrypt) and serve the site over HTTPS.",
    )

def check_http_redirect(final_url):
    """Does http:// automatically redirect to https:// ?"""
    parsed = urlparse(final_url)
    if parsed.scheme != "https":
        return None
    try:
        http_url = "http://" + parsed.netloc + (parsed.path or "/")
        r = requests.get(http_url, timeout=8, allow_redirects=False,
                         headers={"User-Agent": "WebSecurityScanner/2.0"})
    except requests.RequestException:
        return None
    ok = r.status_code in (301, 302, 307, 308) and r.headers.get("Location", "").startswith("https://")
    return finding(
        "HTTP redirects to HTTPS", ok, "Medium",
        "Users reaching the site over insecure HTTP",
        "A02:2021 Cryptographic Failures",
        "http:// redirects to https://" if ok else f"http:// returned status {r.status_code} with no HTTPS redirect",
        "Configure the server to redirect all HTTP traffic to HTTPS (301 redirect).",
    )


def check_cookies(resp):
    raw = getattr(resp.raw, "headers", None)
    cookies = raw.getlist("Set-Cookie") if raw is not None and hasattr(raw, "getlist") else []
    if not cookies:
        return None
    problems = []
    for c in cookies:
        name = c.split("=", 1)[0]
        attrs = [a.strip().lower() for a in c.split(";")[1:]]
        if resp.url.startswith("https://") and "secure" not in attrs:
            problems.append(f"{name}: missing Secure")
        if "httponly" not in attrs:
            problems.append(f"{name}: missing HttpOnly")
        if not any(a.startswith("samesite") for a in attrs):
            problems.append(f"{name}: missing SameSite")
    return finding(
        "Cookie security flags", not problems, "Medium",
        "Session hijacking / CSRF via stolen or forged cookies",
        "A07:2021 Identification and Authentication Failures",
        "All cookies have Secure, HttpOnly, SameSite" if not problems else "; ".join(problems[:4]),
        "Set cookies with Secure; HttpOnly; SameSite=Lax (or Strict).",
    )


def check_disclosure(resp):
    server = resp.headers.get("Server", "")
    powered = resp.headers.get("X-Powered-By", "")
    leaked = bool(powered) or any(ch.isdigit() for ch in server)
    evidence = "No version info exposed"
    if leaked:
        evidence = "; ".join(x for x in (f"Server: {server}" if server else "",
                                         f"X-Powered-By: {powered}" if powered else "") if x)
    return finding(
        "Server version disclosure", not leaked, "Low",
        "Attackers look up known exploits for the exposed software version",
        "A06:2021 Vulnerable and Outdated Components",
        evidence,
        "Hide version details (e.g. 'ServerTokens Prod' in Apache, remove X-Powered-By).",
    )


def check_cors(resp):
    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    threat = "Other websites reading data from this site (CORS abuse)"
    owasp = "A05:2021 Security Misconfiguration"
    fix = ("Allow only trusted origins in Access-Control-Allow-Origin; "
           "never use * with credentials and never reflect the Origin header blindly.")

    if acao is None:
        return finding("CORS policy", True, "Medium", threat, owasp,
                       "No CORS headers (cross-origin access not allowed)", fix)
    if acao == TEST_ORIGIN and acac:
        return finding("CORS policy", False, "High", threat, owasp,
                       "CRITICAL: reflects any origin AND allows credentials", fix)
    if acao == "*" and acac:
        return finding("CORS policy", False, "High", threat, owasp,
                       "CRITICAL: wildcard origin with credentials", fix)
    if acao == TEST_ORIGIN:
        return finding("CORS policy", False, "High", threat, owasp,
                       "HIGH: reflects any Origin header without validation", fix)
    if acao == "*":
        return finding("CORS policy", False, "Medium", threat, owasp,
                       "MEDIUM: Access-Control-Allow-Origin is * (open to all sites)", fix)
    return finding("CORS policy", True, "Medium", threat, owasp,
                   f"CORS limited to {acao}", fix)


# ---------------------------------------------------------------
# 4. Scoring (risk-weighted: High=3, Medium=2, Low=1)
# ---------------------------------------------------------------
def grade(pct):
    for limit, g in ((90, "A"), (75, "B"), (55, "C"), (35, "D")):
        if pct >= limit:
            return g
    return "F"


def scan(url):
    try:
        final_url, resp = fetch(url)
    except requests.RequestException as e:
        return {"url": url, "error": str(e).split("\n")[0][:150]}

    findings = [check_https(final_url)]
    for extra in (check_http_redirect(final_url),):
        if extra:
            findings.append(extra)
    findings += check_headers(resp)
    findings.append(check_cors(resp))
    for extra in (check_cookies(resp), check_disclosure(resp)):
        if extra:
            findings.append(extra)

    total = sum(WEIGHT[f["severity"]] for f in findings)
    earned = sum(WEIGHT[f["severity"]] for f in findings if f["passed"])
    pct = round(earned / total * 100)
    failed = [f for f in findings if not f["passed"]]
    return {
        "url": final_url, "status": resp.status_code, "findings": findings,
        "pct": pct, "grade": grade(pct), "failed": failed,
        "high": sum(1 for f in failed if f["severity"] == "High"),
        "medium": sum(1 for f in failed if f["severity"] == "Medium"),
        "low": sum(1 for f in failed if f["severity"] == "Low"),
        "error": None,
    }


# ---------------------------------------------------------------
# 5. Console output
# ---------------------------------------------------------------
def print_result(r):
    print("\n" + "=" * 70)
    print(f"URL: {r['url']}")
    if r["error"]:
        print(f"  ERROR: {r['error']}")
        return
    print(f"Security score: {r['pct']}%   Grade: {r['grade']}   "
          f"Issues -> High: {r['high']}, Medium: {r['medium']}, Low: {r['low']}")
    print("-" * 70)
    for f in r["findings"]:
        mark = "[PASS]" if f["passed"] else "[FAIL]"
        sev = "" if f["passed"] else f" ({f['severity']} risk)"
        print(f"  {mark} {f['check']}{sev}")
        if not f["passed"]:
            print(f"         Threat : {f['threat']}")
            print(f"         Found  : {f['evidence']}")
            print(f"         OWASP  : {f['owasp']}")
            print(f"         Fix    : {f['fix']}")


# ---------------------------------------------------------------
# 6. Reports
# ---------------------------------------------------------------
def save_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["URL", "Score %", "Grade", "High", "Medium", "Low", "Failed checks", "Error"])
        for r in results:
            if r["error"]:
                w.writerow([r["url"], "", "", "", "", "", "", r["error"]])
            else:
                w.writerow([r["url"], r["pct"], r["grade"], r["high"], r["medium"], r["low"],
                            "; ".join(x["check"] for x in r["failed"]) or "None", ""])


def save_html(results, path):
    e = html.escape
    colors = {"A": "#2e7d32", "B": "#7cb342", "C": "#f9a825", "D": "#ef6c00", "F": "#c62828"}
    sev_color = {"High": "#c62828", "Medium": "#ef6c00", "Low": "#f9a825"}
    cards = []
    for r in results:
        if r["error"]:
            cards.append(f"<div class='card'><h3>{e(r['url'])}</h3><p>Error: {e(r['error'])}</p></div>")
            continue
        rows = ""
        for f in r["findings"]:
            if f["passed"]:
                rows += (f"<tr><td>{e(f['check'])}</td><td class='ok'>PASS</td><td></td>"
                         f"<td></td><td>{e(f['evidence'])}</td><td></td></tr>")
            else:
                rows += (f"<tr><td>{e(f['check'])}</td><td class='bad'>FAIL</td>"
                         f"<td style='color:{sev_color[f['severity']]};font-weight:bold'>{f['severity']}</td>"
                         f"<td>{e(f['threat'])}<br><small>{e(f['owasp'])}</small></td>"
                         f"<td>{e(f['evidence'])}</td><td>{e(f['fix'])}</td></tr>")
        cards.append(
            f"<div class='card'><h3>{e(r['url'])} "
            f"<span class='grade' style='background:{colors[r['grade']]}'>{r['grade']}</span></h3>"
            f"<p>Security score: <b>{r['pct']}%</b> | Issues: "
            f"<b>{r['high']}</b> High, <b>{r['medium']}</b> Medium, <b>{r['low']}</b> Low</p>"
            f"<div class='scroll'><table><tr><th>Check</th><th>Result</th><th>Risk</th>"
            f"<th>Threat / OWASP</th><th>Finding</th><th>Mitigation</th></tr>{rows}</table></div></div>"
        )
    page = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Web Security Scan Report</title>
<style>
body{{font-family:Arial,sans-serif;max-width:1100px;margin:30px auto;padding:0 15px;background:#f5f5f5}}
.card{{background:#fff;padding:15px 20px;margin:15px 0;border-radius:8px;box-shadow:0 1px 3px #0002}}
.scroll{{overflow-x:auto}}table{{width:100%;border-collapse:collapse}}
th,td{{text-align:left;padding:6px;border-bottom:1px solid #ddd;font-size:13px;vertical-align:top}}
.ok{{color:#2e7d32;font-weight:bold}}.bad{{color:#c62828;font-weight:bold}}
.grade{{color:#fff;padding:2px 10px;border-radius:5px;font-size:16px}}
</style></head><body>
<h1>Web Security Scan Report</h1>
<p>Generated: {datetime.now():%d %b %Y, %H:%M} | IBM SkillsBuild National Cybersecurity Bootcamp project</p>
<p><small>Passive checks only. Risk = how serious the missing protection is (High / Medium / Low).</small></p>
{''.join(cards)}
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)


# ---------------------------------------------------------------
# 7. Main
# ---------------------------------------------------------------
def load_urls(args):
    urls = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            urls += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    return urls


def main():
    p = argparse.ArgumentParser(description="Automated Web Security Scanner")
    p.add_argument("urls", nargs="*", help="URL(s) to scan")
    p.add_argument("-f", "--file", help="Text file with one URL per line")
    p.add_argument("-o", "--output", default="report", help="Report name (no extension)")
    args = p.parse_args()

    urls = load_urls(args)
    if not urls:
        p.print_help()
        sys.exit(1)

    print("Reminder: scan only sites you own or have permission to test.")
    results = []
    for u in urls:
        r = scan(u)
        print_result(r)
        results.append(r)

    save_csv(results, args.output + ".csv")
    save_html(results, args.output + ".html")
    print(f"\nReports saved: {args.output}.csv and {args.output}.html")


if __name__ == "__main__":
    main()
