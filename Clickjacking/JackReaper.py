import requests
from datetime import datetime

def check_clickjacking(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; ClickjackScanner/1.0)"
        }

        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        response_headers = {k.lower(): v for k, v in response.headers.items()}

        xfo = response_headers.get("x-frame-options")
        csp = response_headers.get("content-security-policy")

        result = []
        result.append(f"Scan Report for: {url}")
        result.append(f"Scanned At: {datetime.now()}")
        result.append("="*60)
        result.append(f"X-Frame-Options: {xfo}")
        result.append(f"Content-Security-Policy: {csp}")
        result.append("")

        vulnerable = True

        if xfo:
            xfo = xfo.lower()
            if "deny" in xfo:
                result.append("✅ X-Frame-Options set to DENY → Strong protection.")
                vulnerable = False
            elif "sameorigin" in xfo:
                result.append("✅ X-Frame-Options set to SAMEORIGIN → Moderate protection.")
                vulnerable = False
            elif "allow-from" in xfo:
                result.append("⚠️ X-Frame-Options set to ALLOW-FROM → Deprecated.")
                vulnerable = True
            else:
                result.append("⚠️ X-Frame-Options present but value is unclear.")
        
        if csp:
            csp = csp.lower()
            if "frame-ancestors" in csp:
                frame_ancestors_value = csp.split("frame-ancestors")[1].split(";")[0].strip()
                if "'none'" in frame_ancestors_value:
                    result.append("✅ CSP frame-ancestors 'none' → Strong protection.")
                    vulnerable = False
                elif "'self'" in frame_ancestors_value:
                    result.append("✅ CSP frame-ancestors 'self' → Moderate protection.")
                    vulnerable = False
                else:
                    result.append(f"⚠️ CSP frame-ancestors value: {frame_ancestors_value} → Check manually.")
                    vulnerable = True

        if not xfo and not csp:
            result.append("❌ No X-Frame-Options or CSP frame-ancestors found.")
        elif vulnerable:
            result.append("⚠️ Headers found but insufficient to ensure full protection.")

        result.append("")

        if vulnerable:
            result.append("🔴 Clickjacking Vulnerability Detected!\n")
            result.append("🧠 What is Clickjacking?")
            result.append("Clickjacking is an attack where a malicious site tricks a user into clicking on something on a legitimate site, hidden under an invisible frame.")
            result.append("\n🎯 How attackers exploit it:")
            result.append("- Embed the legitimate site using <iframe>")
            result.append("- Make iframe invisible or semi-transparent")
            result.append("- Overlay a fake button or trap element")
            result.append("- User thinks they're clicking a visible UI but clicks something hidden underneath")
            result.append("\n🛡️ Recommended Mitigations:")
            result.append("- Set response header: X-Frame-Options: DENY or SAMEORIGIN")
            result.append("- Or use Content-Security-Policy: frame-ancestors 'none';")
            result.append("- Avoid embedding sensitive actions in pages that can be framed")
        else:
            result.append("🟢 This website is NOT vulnerable to clickjacking.")

        filename = url.replace("https://", "").replace("http://", "").replace("/", "_") + "_clickjack_report.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(result))


        print(f"[+] Report saved to: {filename}")

    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")

# ===== Run Scanner =====
target = input("Enter the target website URL (with https://): ").strip()
check_clickjacking(target)
