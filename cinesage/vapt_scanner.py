import urllib.parse
import socket
import ssl
import httpx
import asyncio
from datetime import datetime, timezone
import dns.resolver

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    _HAVE_CRYPTO = True
except ImportError:
    _HAVE_CRYPTO = False

COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443]

async def check_port(host, port, timeout=1.0):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port, "OPEN"
    except Exception:
        return port, "CLOSED/FILTERED"

async def run_vapt_scan(target_url: str, domain_context: str = "Education"):
    findings = []
    
    # 1. Target Validation & Scope
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    parsed_url = urllib.parse.urlparse(target_url)
    hostname = parsed_url.hostname
    if not hostname:
        return {"error": "Invalid target URL format."}
        
    port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
    
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except Exception as e:
        return {"error": f"DNS Resolution failed for {hostname}: {str(e)}"}

    scope_info = {
        "target": target_url,
        "hostname": hostname,
        "resolved_ip": resolved_ip,
        "protocol": parsed_url.scheme,
        "port": port,
        "domain_context": domain_context,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    # 2. Port Scanning
    open_ports = []
    tasks = [check_port(resolved_ip, p) for p in COMMON_PORTS]
    results = await asyncio.gather(*tasks)
    for p, state in results:
        if state == "OPEN":
            open_ports.append({"port": p, "protocol": "TCP", "state": state, "service": "unknown", "risk": "Low" if p in [80, 443] else "Medium"})
            if p not in [80, 443]:
                findings.append({
                    "name": f"Open Port {p}",
                    "category": "Network",
                    "severity": "Medium",
                    "description": f"Port {p} is open and accessible from the outside.",
                    "evidence": f"TCP Connection to {resolved_ip}:{p} succeeded.",
                    "impact": "Exposed services can increase the attack surface.",
                    "recommendation": "Restrict access to necessary ports only."
                })

    # 3. HTTP Security & Headers
    headers_info = {}
    redirect_chain = []
    http_methods = []
    tls_info = {}
    mitm_risk = "LOW"
    mitm_reasons = []

    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
            response = await client.get(target_url)
            redirect_chain = [str(r.url) for r in response.history] + [str(response.url)]
            headers_info = dict(response.headers)
            
            # Check methods
            try:
                opt_res = await client.options(target_url)
                if 'allow' in opt_res.headers:
                    http_methods = opt_res.headers['allow'].split(', ')
            except:
                pass
                
    except Exception as e:
        findings.append({
            "name": "Target Unreachable",
            "category": "Network",
            "severity": "High",
            "description": f"Failed to connect to the target via HTTP/HTTPS: {str(e)}",
            "evidence": str(e),
            "impact": "Application availability or network accessibility issues.",
            "recommendation": "Check target status and network configuration."
        })

    # Check headers
    hsts = headers_info.get("strict-transport-security", "").lower()
    csp = headers_info.get("content-security-policy", "").lower()
    xfo = headers_info.get("x-frame-options", "").lower()
    
    if not hsts and parsed_url.scheme == "https":
        findings.append({
            "name": "Missing HSTS Header",
            "category": "HTTP Security",
            "severity": "Medium",
            "description": "HTTP Strict Transport Security (HSTS) header is missing.",
            "evidence": "Strict-Transport-Security header not found in response.",
            "impact": "Susceptible to MITM attacks via SSL stripping.",
            "recommendation": "Implement HSTS with a long max-age."
        })
        mitm_risk = "MEDIUM"
        mitm_reasons.append("HSTS missing")
    elif parsed_url.scheme == "https":
        mitm_reasons.append("HSTS enabled")
        
    if not csp:
        findings.append({
            "name": "Missing Content-Security-Policy",
            "category": "HTTP Security",
            "severity": "Low",
            "description": "CSP header is missing.",
            "evidence": "Content-Security-Policy header not found.",
            "impact": "Increases risk of Cross-Site Scripting (XSS).",
            "recommendation": "Implement a strong CSP."
        })
        
    if not xfo and "frame-ancestors" not in csp:
        findings.append({
            "name": "Missing X-Frame-Options",
            "category": "HTTP Security",
            "severity": "Medium",
            "description": "The application may be susceptible to clickjacking.",
            "evidence": "X-Frame-Options not found.",
            "impact": "Attackers can frame the site to trick users.",
            "recommendation": "Configure X-Frame-Options to DENY or SAMEORIGIN."
        })
        
    server_header = headers_info.get("server", "")
    if server_header:
        findings.append({
            "name": "Server Software Disclosure",
            "category": "Information Disclosure",
            "severity": "Informational",
            "description": "Server software version is disclosed.",
            "evidence": f"Server: {server_header}",
            "impact": "Helps attackers identify potential vulnerabilities in the specific software version.",
            "recommendation": "Remove or obscure the Server header."
        })

    # 4. SSL/TLS Certificate Analysis & Expiration Verification
    cert_info = {}
    if parsed_url.scheme == "https":
        mitm_reasons.append("HTTPS enabled")
        
        # Step 4a: Validate standard trust store (CA validation & hostname match)
        is_valid = False
        validation_error = None
        try:
            verify_ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=3) as sock:
                with verify_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    is_valid = True
        except ssl.SSLCertVerificationError as e:
            validation_error = getattr(e, 'verify_message', str(e))
        except Exception as e:
            validation_error = str(e)
            
        # Step 4b: Retrieve peer certificate and extract cryptographic metadata
        try:
            unverified_ctx = ssl._create_unverified_context()
            with socket.create_connection((hostname, port), timeout=3) as sock:
                with unverified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_version = ssock.version()
                    cipher = ssock.cipher()
                    cipher_name = cipher[0] if cipher else "Unknown"
                    raw_der = ssock.getpeercert(binary_form=True)
                    
                    days_left = None
                    expiry_date_str = "Unknown"
                    issued_date_str = "Unknown"
                    is_expired = False
                    issuer_str = "Unknown"
                    subject_str = hostname

                    if _HAVE_CRYPTO and raw_der:
                        try:
                            parsed_cert = x509.load_der_x509_certificate(raw_der)
                            now_utc = datetime.now(timezone.utc)
                            not_after_utc = parsed_cert.not_valid_after_utc
                            not_before_utc = parsed_cert.not_valid_before_utc
                            days_left = (not_after_utc - now_utc).days
                            is_expired = days_left < 0
                            expiry_date_str = not_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
                            issued_date_str = not_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
                            
                            try:
                                subject_str = parsed_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                            except Exception:
                                subject_str = parsed_cert.subject.rfc4514_string()
                                
                            try:
                                issuer_str = parsed_cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
                            except Exception:
                                try:
                                    issuer_str = parsed_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                                except Exception:
                                    issuer_str = parsed_cert.issuer.rfc4514_string()
                        except Exception:
                            pass
                    
                    cert_info = {
                        "valid": is_valid,
                        "validation_error": validation_error,
                        "days_left": days_left,
                        "is_expired": is_expired,
                        "expiry_date": expiry_date_str,
                        "issued_date": issued_date_str,
                        "issuer": issuer_str,
                        "subject": subject_str,
                        "version": tls_version,
                        "cipher": cipher_name,
                    }

                    # Finding: Weak TLS version
                    if tls_version in ["TLSv1", "TLSv1.1"]:
                        findings.append({
                            "name": "Weak TLS Version",
                            "category": "SSL/TLS",
                            "severity": "High",
                            "description": f"Target supports outdated TLS version: {tls_version}",
                            "evidence": f"Negotiated version: {tls_version}",
                            "impact": "Susceptible to known cryptographic downgrade attacks.",
                            "recommendation": "Disable TLS 1.0 and TLS 1.1. Enforce TLS 1.2 or 1.3."
                        })
                        mitm_risk = "HIGH"
                        mitm_reasons.append(f"Weak TLS version ({tls_version})")
                    else:
                        mitm_reasons.append(f"Strong TLS version ({tls_version})")

                    # Finding: Invalid or untrusted certificate
                    if not is_valid:
                        findings.append({
                            "name": "Untrusted or Invalid SSL Certificate",
                            "category": "SSL/TLS",
                            "severity": "High",
                            "description": f"SSL certificate trust validation failed: {validation_error}",
                            "evidence": f"Validation failure: {validation_error}",
                            "impact": "Users encounter browser security warnings; high risk of MITM impersonation.",
                            "recommendation": "Install a trusted SSL certificate issued by a recognized Certificate Authority for this domain."
                        })
                        mitm_risk = "HIGH"
                        mitm_reasons.append(f"Invalid SSL cert ({validation_error})")

                    # Finding: Expired certificate
                    if is_expired:
                        findings.append({
                            "name": "SSL Certificate Expired",
                            "category": "SSL/TLS",
                            "severity": "Critical",
                            "description": f"The SSL certificate expired {abs(days_left)} day(s) ago on {expiry_date_str}.",
                            "evidence": f"Expired: {expiry_date_str} (Days remaining: {days_left})",
                            "impact": "All HTTPS traffic is flagged as dangerous. Browsers reject connection.",
                            "recommendation": "Renew and replace the expired certificate immediately."
                        })
                        mitm_risk = "HIGH"
                        mitm_reasons.append(f"Expired certificate ({abs(days_left)} days overdue)")
                    elif days_left is not None and days_left <= 15:
                        findings.append({
                            "name": "SSL Certificate Expiring Imminently",
                            "category": "SSL/TLS",
                            "severity": "High",
                            "description": f"The SSL certificate will expire in {days_left} day(s) on {expiry_date_str}.",
                            "evidence": f"Expiration: {expiry_date_str} ({days_left} days remaining)",
                            "impact": "Immediate service disruption upon expiration.",
                            "recommendation": "Renew the SSL certificate promptly before it expires."
                        })
                    elif days_left is not None and days_left <= 30:
                        findings.append({
                            "name": "SSL Certificate Renewal Required",
                            "category": "SSL/TLS",
                            "severity": "Medium",
                            "description": f"The SSL certificate expires in {days_left} days on {expiry_date_str}.",
                            "evidence": f"Expiration: {expiry_date_str} ({days_left} days remaining)",
                            "impact": "Upcoming certificate expiration requires administrative action.",
                            "recommendation": "Schedule certificate renewal with your CA."
                        })
                    elif is_valid and days_left is not None:
                        mitm_reasons.append(f"Valid SSL cert ({days_left} days left)")

        except Exception as e:
            cert_info = {"valid": False, "error": str(e)}
            findings.append({
                "name": "SSL/TLS Handshake Error",
                "category": "SSL/TLS",
                "severity": "High",
                "description": f"Failed to retrieve or evaluate certificate: {str(e)}",
                "evidence": str(e),
                "impact": "Users may encounter SSL warnings; encrypted communications impaired.",
                "recommendation": "Verify SSL listener and certificate binding configuration."
            })
            mitm_risk = "HIGH"
            mitm_reasons.append("Certificate handshake failure")
    else:
        mitm_risk = "HIGH"
        mitm_reasons.append("HTTP endpoint used (no encryption)")
        findings.append({
            "name": "Unencrypted Communication",
            "category": "Transport Security",
            "severity": "High",
            "description": "The application is accessed over HTTP.",
            "evidence": "URL scheme is http.",
            "impact": "Credentials and data can be intercepted in transit.",
            "recommendation": "Enforce HTTPS everywhere."
        })

    # DNS Recon
    dns_records = {}
    try:
        for qtype in ['A', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(hostname, qtype)
                dns_records[qtype] = [str(rdata) for rdata in answers]
            except:
                pass
    except:
        pass

    # Score calculation
    severity_weights = {"Critical": 25, "High": 15, "Medium": 5, "Low": 2, "Informational": 0}
    penalty = sum(severity_weights.get(f["severity"], 0) for f in findings)
    score = max(0, 100 - penalty)

    return {
        "scope": scope_info,
        "open_ports": open_ports,
        "headers": {k: v for k, v in headers_info.items() if k.lower() in ["server", "x-powered-by", "content-security-policy", "x-frame-options", "strict-transport-security", "set-cookie"]},
        "tls": cert_info,
        "dns": dns_records,
        "redirect_chain": redirect_chain,
        "mitm": {
            "risk": mitm_risk,
            "reasons": mitm_reasons
        },
        "findings": findings,
        "score": score
    }
