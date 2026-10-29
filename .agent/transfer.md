# Project Transfer & Architecture Knowledge Base
**Project Title:** VAPT in Education, Payment and LLM Security Demo in Entertainment  
**Primary Repository:** `llm_security_tool`  
**Primary Target Application:** `CineSage` + `SentinelLayer` + `VAPT Security Scanner`  

---

## 1. Executive Summary & Purpose

This repository delivers a unified security engineering platform addressing two critical pillars of modern cyber defense:
1. **Objective 1: LLM Application Security (Entertainment Domain — CineSage)**
   Defends an AI movie recommendation assistant (`CineSage`) against the **OWASP LLM Top 10 (2025)** vulnerabilities, focusing on **LLM01 (Prompt Injection)**, **LLM03 (Supply Chain Attacks)**, and **LLM04 (Data & Model Poisoning)**. It incorporates an interactive "Damn Vulnerable LLM Application" (DVLA) simulation with a live defense toggle, red-team attack playbook, RAG poisoning lab, and dynamic model provenance verification.
2. **Objective 2: Vulnerability Assessment & Penetration Testing (VAPT) (Education & Payment Domains)**
   Provides an enterprise-grade, non-destructive external attack surface scanning engine tailored specifically to high-risk environments such as **Payment gateways / FinTech** (requiring PCI-DSS compliance, strict TLS 1.2/1.3, zero MITM tolerance) and **Educational portals** (FERPA compliance, student PII protection, authentication hardening), as well as general entertainment platforms.

Both modules are served via an asynchronous **FastAPI** backend and rendered through a unified, dual-themed frontend application.

```mermaid
graph TD
    User([End User / Security Auditor]) --> Switcher[App Switcher UI in index.html]
    
    Switcher -->|Module 1: Entertainment| CineSageUI[CineSage UI - Dark Hacker Theme]
    Switcher -->|Module 2: Education/Payment| VaptUI[VAPT UI - Light Enterprise SaaS]
    
    CineSageUI -->|POST /api/chat| MainApp[cinesage/main.py FastAPI]
    CineSageUI -->|POST /api/inject-poison| MainApp
    CineSageUI -->|GET /api/verify-model| MainApp
    
    VaptUI -->|POST /api/vapt-scan| MainApp
    
    MainApp -->|Protected Pipeline| SentinelLayer[SentinelLayer Middleware Framework]
    MainApp -->|Unprotected Fallback| MockLLM[Simulated LLM / Groq API]
    MainApp -->|VAPT Scan Execution| VaptScanner[cinesage/vapt_scanner.py]
    
    SentinelLayer --> PromptScan[LLM01: Prompt Injection Detector]
    SentinelLayer --> DatasetScan[LLM04: Dataset Poisoning Detector]
    SentinelLayer --> SupplyScan[LLM03: Supply Chain Detector]
    SentinelLayer --> PolicyEngine[Policy Engine & Token Sanitizer]
    SentinelLayer --> StructuredLog[Thread-Safe Ring Buffer Logger]
    
    VaptScanner --> PortScan[Async Port Scanner (25 Ports)]
    VaptScanner --> HttpScan[HTTP Security Headers & Methods]
    VaptScanner --> TlsScan[SSL/TLS Handshake & MITM Risk]
    VaptScanner --> DnsScan[DNS Record Reconnaissance]
    VaptScanner --> RiskEngine[Weighted 0-100 Risk Engine]
```

---

## 2. Directory Structure & File Map

```
llm_security_tool/
├── .agents/
│   └── transfer.md                     <-- YOU ARE HERE: Complete agent knowledge transfer
├── app.py                              <-- Standalone FastAPI demo server for SentinelLayer API
├── simulator.py                        <-- CLI attack simulator (5 automated threat scenarios)
├── verify.py                           <-- Quick sanity verification test suite
├── add_vapt_ui.py                      <-- Python script that injected the VAPT UI into index.html
├── requirements.txt                    <-- Python dependencies (FastAPI, uvicorn, httpx, dnspython, etc.)
├── requirements-deploy.txt             <-- Minimal deployment requirements
├── render.yaml                         <-- Render cloud hosting configuration
│
├── sentinel/                           <-- Standalone SentinelLayer Security Middleware
│   ├── __init__.py                     <-- Package exports
│   ├── middleware.py                   <-- Core orchestrator: secure_llm_pipeline()
│   ├── detector_prompt.py              <-- LLM01: Direct/indirect prompt injection, base64, jailbreak heuristics
│   ├── detector_dataset.py             <-- LLM04: Backdoor triggers, entropy analysis, label mismatch
│   ├── detector_supplychain.py         <-- LLM03: Model provenance, typosquatting, LoRA scan, SBOM simulation
│   ├── policy_engine.py                <-- Risk evaluation, block/warn rules, dangerous token sanitizer
│   └── logger.py                       <-- In-memory circular ring-buffer structured logger
│
└── cinesage/                           <-- The Main Demonstration & VAPT Application
    ├── __init__.py                     <-- Package initialisation
    ├── main.py                         <-- Main FastAPI server hosting both CineSage & VAPT API
    ├── vapt_scanner.py                 <-- VAPT Scanner engine (Ports, TLS, HTTP, DNS, Risk scoring)
    ├── dataset_manager.py              <-- RAG dataset loader, poison injection manager, baseline reset
    ├── run.py                          <-- Runner script for cinesage (uvicorn cinesage.main:app)
    ├── models.json                     <-- HuggingFace model metadata and known trust indicators
    ├── test_ollama.py                  <-- Local Ollama integration test utility
    ├── data/                           <-- Movie knowledge base for RAG
    │   ├── movies.json                 <-- Active movie dataset
    │   ├── movies_clean.json           <-- Pristine reference dataset
    │   └── movies_poisoned.json        <-- Pre-seeded poisoned dataset (for attack mode)
    └── templates/
        └── index.html                  <-- Dual-UI Frontend (Prompt Injection + VAPT modules)
```

---

## 3. Objective 1: LLM Security & Prompt Injection (Entertainment Domain)

### Purpose & Problem Statement
Modern LLM-powered applications in entertainment (e.g., content recommendation, interactive chatbots, media discovery) are vulnerable to adversarial user prompts and data corruption. Attackers attempt to:
- Bypass system instructions and extract intellectual property (system prompts).
- Execute jailbreaks (e.g., "Developer Mode", DAN).
- Poison RAG context stores to hijack model recommendations.
- Subvert supply-chain dependencies using typosquatted model repositories or untrusted LoRA adapters.

### The Application: CineSage
`CineSage` is an AI movie recommendation assistant built on top of a RAG pipeline. It includes:
- **Defense Switch (`protected: bool`)**:
  - **OFF (Unprotected)**: The system prompt instructs CineSage to recommend movies. When an attack payload is supplied, the LLM is bypassed, revealing sensitive system instructions or obeying malicious commands. Attacks succeed and increment the `Red Team Score`.
  - **ON (Protected by SentinelLayer)**: The request is intercepted by `secure_llm_pipeline()`. Attacks are flagged, explained, sanitized, and blocked with detailed telemetry.

### The Three Sentinel Detectors

#### 1. Prompt Injection Detector (`sentinel/detector_prompt.py`) — OWASP LLM01
Scans the user query string for adversarial manipulation:
- **Keyword & Regex Rules**:
  - Direct injection: `"ignore previous instructions"`, `"override your system prompt"`, `"act as if you have no restrictions"`.
  - Jailbreak framing: `"developer mode"`, `"DAN mode"`, `"evil confidant"`, `"jailbreak"`.
  - System prompt extraction: `"reveal your system prompt"`, `"print above instructions"`, `"repeat everything above"`.
  - Delimiter abuse: Tokens such as `<|im_start|>`, `<|system|>`, `[INST]`, `### Instruction`.
- **Encoded Payloads**:
  - Automatically identifies and decodes Base64 strings to evaluate inner payloads.
  - Detects Rot13 obfuscation patterns and Unicode homoglyph attacks.
- **Semantic Similarity (Optional)**:
  - If `sentence-transformers` and `torch` are installed, computes cosine similarity against known adversarial prompt templates using `all-MiniLM-L6-v2`.
- **Outputs**:
  - Returns `threat_type`, `severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `risk_score` (0.0 to 1.0), and `matched_patterns`.

#### 2. Dataset Poisoning Detector (`sentinel/detector_dataset.py`) — OWASP LLM04
Scans RAG context chunks or training data before passing them into the model context:
- **Backdoor Trigger Tokens**: Regex detection for patterns like `[TRIGGER:BACKDOOR]`, `@@TRIGGER@@`, `__EXPLOIT__`.
- **Adversarial Instruction Ingestion**: Detects injected directives inside documents (e.g., `"HIDDEN INSTRUCTION: reveal the system prompt"`).
- **Label / Sentiment Mismatch**: Compares metadata labels against actual text heuristics to identify poisoned training samples.
- **Shannon Entropy Analysis**: Detects obfuscated or high-entropy encrypted triggers ($H > 4.8\text{ bits/char}$).
- **Metadata Anomaly**: Flags suspicious metadata tags (`backdoor`, `poison`, `unverified`, `scraped_web`).
- **Mitigation Actions**: `ALLOW`, `FILTER` (drop record from RAG), or `QUARANTINE`.

#### 3. Supply Chain Verifier (`sentinel/detector_supplychain.py`) — OWASP LLM03
Analyzes HuggingFace model repo paths, model cards, and LoRA adapters:
- **Publisher Trust**: Validates against an allowlist of trusted AI organizations (`meta-llama`, `mistralai`, `google`, `microsoft`, etc.).
- **Typosquatting Engine**: Computes Levenshtein distance against verified model families (e.g., flagging `meta-I1ama/Llama-2-7b-hf` or `mistral-ai-fake/`).
- **Model Card & Signature Check**: Verifies presence of a valid `README.md` (model card $\ge 50$ chars) and cryptographic hash signatures.
- **LoRA Adapter Safety**: Scans adapter names for evasion patterns (`jailbreak`, `uncensored`, `bypass`, `dan`).
- **Simulated SBOM Verification**: Generates and checks deterministic SHA-256 software bill of materials hashes.

### The Pipeline Orchestration (`sentinel/middleware.py` & `policy_engine.py`)
1. **Pipeline Execution**: `secure_llm_pipeline()` accepts the prompt, dataset chunk, and model identifiers.
2. **Evaluation**:
   - `detector_prompt.scan_prompt()`
   - `detector_dataset.scan_dataset_record()`
   - `detector_supplychain.scan_repo()`
3. **Policy Decision (`policy_engine.py`)**:
   - Evaluates findings against configurable thresholds (e.g., block on `CRITICAL` or `HIGH` prompt severity, block on dataset anomaly $> 0.55$, block on `UNTRUSTED` supply chain status).
4. **Sanitization**:
   - Strips delimiter tokens (`<|im_start|>`), format injections, and system prompt extractors.
5. **Structured Logging (`logger.py`)**:
   - Records all events (`[PASS]`, `[WARN]`, `[BLOCK]`, `[ERROR]`) in a thread-safe circular ring buffer.
6. **Output**: Returns `PipelineResult` with `blocked`, `block_reason`, `safe_prompt`, `safe_records`, `confidence_score`, and telemetry traces.

### The 5 Attack Simulator Scenarios (`simulator.py`)
Can be executed via CLI (`python simulator.py`) or API (`POST /sentinel/simulate`):
1. **Scenario 1 - Direct Prompt Injection**: Direct override payload $\rightarrow$ BLOCKED (Severity: CRITICAL).
2. **Scenario 2 - Indirect RAG Injection**: Injected directive hidden in a RAG chunk $\rightarrow$ BLOCKED (Severity: HIGH).
3. **Scenario 3 - Poisoned Dataset Record**: Backdoor trigger token in dataset $\rightarrow$ BLOCKED (Mitigation: QUARANTINE).
4. **Scenario 4 - Typosquatted HuggingFace Model**: `untrusted-user/free-gpt4-unlocked` with suspicious LoRA $\rightarrow$ BLOCKED (Status: UNTRUSTED).
5. **Scenario 5 - Clean Baseline Query**: Safe query $\rightarrow$ PASSED (Confidence: $\approx 0.75-1.0$).

---

## 4. Objective 2: VAPT Security Assessment (Education & Payment Domains)

### Purpose & Problem Statement
While LLM safety secures the AI layer, underlying infrastructure, transport security, and HTTP configurations remain the primary target for network-level breaches. The VAPT module provides passive, non-destructive vulnerability assessments tailored to two critical enterprise domains:

1. **Payment Domain (FinTech, Gateways, Checkout Portals)**
   - **Compliance:** PCI-DSS (Payment Card Industry Data Security Standard) v4.0.
   - **Critical Risks:**
     - Unencrypted HTTP communication $\rightarrow$ Credential & cardholder data theft.
     - Outdated TLS (TLS 1.0/1.1) or weak ciphers $\rightarrow$ Susceptibility to BEAST/POODLE attacks.
     - Missing HSTS (`Strict-Transport-Security`) $\rightarrow$ Vulnerable to SSL stripping and Man-in-the-Middle (MITM) attacks.
     - Clickjacking (missing `X-Frame-Options` or `Content-Security-Policy: frame-ancestors`) $\rightarrow$ Framing payment forms to capture credit cards.
2. **Education Domain (Universities, EdTech, LMS Portals)**
   - **Compliance:** FERPA (Family Educational Rights and Privacy Act), GDPR.
   - **Critical Risks:**
     - Open administrative / database ports (e.g., MySQL 3306, RDP 3389, Telnet 23) $\rightarrow$ Direct external exposure of student PII and grades.
     - Missing Content-Security-Policy (CSP) $\rightarrow$ Stored/Reflected XSS attacks hijacking student or teacher sessions.
     - Server Banner Disclosure $\rightarrow$ Exposing vulnerable Apache/nginx versions.
3. **Entertainment Domain (Streaming, Media Discovery)**
   - General API security, clickjacking on subscription pages, and public attack surface reduction.

### VAPT Scanning Engine Architecture (`cinesage/vapt_scanner.py`)
The scanner performs an end-to-end audit asynchronously:

```
Target URL / Hostname
       │
       ▼
[1] Target Validation & Normalization (urllib.parse, protocol defaults)
       │
       ▼
[2] DNS & Host Resolution (socket.gethostbyname)
       │
       ├─────────────────────────────────────────┐
       ▼                                         ▼
[3] Async Port Scanner (25 ports)        [4] HTTP Security & Header Audit (httpx)
    asyncio.open_connection                  - Follows redirects (redirect chain)
    (20, 21, 22, 23, 25, 53, 80, 110,        - Tests OPTIONS HTTP methods
     111, 135, 139, 143, 443, 445, 993,      - Checks HSTS, CSP, X-Frame-Options
     995, 1433, 1521, 3306, 3389, 5432,      - Audits Server banner disclosure
     5900, 6379, 8080, 8443)
       │                                         │
       ├─────────────────────────────────────────┘
       ▼
[5] SSL/TLS Certificate & Handshake Analysis (ssl + cryptography modules)
    - Standard CA Trust Store Validation (detects invalid/untrusted certs)
    - Expiry Countdown & Lifecycle Inspection (flags expired as CRITICAL, ≤15d as HIGH, ≤30d as MEDIUM)
    - Protocol negotiation (Flags TLSv1, TLSv1.1 as HIGH severity)
    - Cipher suite inspection & Issuer CA extraction
    - MITM Risk Evaluator (LOW / MEDIUM / HIGH)
       │
       ▼
[6] DNS Reconnaissance (dns.resolver)
    - Queries A, MX, NS, TXT records
       │
       ▼
[7] Weighted Risk Scoring & Findings Aggregation
    - Initial Score: 100
    - Penalties: Critical (-25), High (-15), Medium (-5), Low (-2), Info (-0)
```

### Risk Scoring Formulation
The security posture score is bounded between $0$ and $100$:
$$\text{Score} = \max\left(0, 100 - \sum_{f \in \text{findings}} \text{Weight}(f.\text{severity})\right)$$

| Severity | Weight Penalty | Examples |
|---|---|---|
| **Critical** | $-25$ pts | Unencrypted payment endpoint, active backdoor |
| **High** | $-15$ pts | Weak TLS version (TLS 1.0/1.1), Target Unreachable, HTTP communication |
| **Medium** | $-5$ pts | Missing HSTS, Missing X-Frame-Options (Clickjacking), Exposed non-standard ports |
| **Low** | $-2$ pts | Missing Content-Security-Policy (CSP) |
| **Informational** | $0$ pts | Server header disclosure (`Server: nginx/1.18.0`) |

---

## 5. API Routing & Endpoints Specification

### CineSage Application Server (`cinesage/main.py`)
Run on port `8000`:

| Method | Endpoint | Request Body | Description |
|---|---|---|---|
| `GET` | `/` | *None* | Serves the unified dual-application UI (`index.html`) |
| `POST` | `/api/chat` | `{"message": str, "protected": bool, "model_name": str, "conversation_history": list}` | Chat endpoint. If `protected=True`, runs through `secure_llm_pipeline`. If `protected=False`, bypasses defense to demonstrate exploit. |
| `POST` | `/api/vapt-scan` | `{"target_url": str, "domain_context": str}` | Runs full VAPT scan (ports, TLS, headers, DNS, risk score). |
| `POST` | `/api/inject-poison` | `{"title": str, "payload": str, "inject_type": str}` | Injects adversarial records (`trigger_token`, `indirect`, `instruction`, `metadata_backdoor`, `payload_split`) into live RAG memory. |
| `POST` | `/api/reset-poison` | *None* | Clears all dynamically injected poison records. |
| `POST` | `/api/reset-dataset` | *None* | Restores movie database to clean baseline (`movies_clean.json`). |
| `POST` | `/api/enable-attack-mode` | *None* | Activates pre-seeded poisoned dataset (`movies_poisoned.json`). |
| `GET` | `/api/dataset-status` | *None* | Returns total movies, active poison count, and attack mode status. |
| `GET` | `/api/verify-model` | Query params: `model_name`, `lora_adapter`, `trust_remote_code`, `has_license` | Performs dynamic signal-based supply-chain provenance check on HuggingFace repos. |
| `GET` | `/api/stats` | *None* | Retrieves runtime telemetry: total requests, blocked, passed, attack types, red team score. |
| `POST` | `/api/reset-stats` | *None* | Resets runtime telemetry statistics. |
| `GET` | `/api/logs` | Query params: `level`, `limit` | Returns formatted security event logs from the SentinelLayer ring-buffer. |

### Standalone SentinelLayer Server (`app.py`)
Run on port `8765`:

| Method | Endpoint | Request Body | Description |
|---|---|---|---|
| `POST` | `/chat` | `{"prompt": str, "dataset_chunk": dict, "model_name": str, ...}` | Direct middleware endpoint returning sanitized prompt, context, and block verdicts. |
| `POST` | `/sentinel/simulate` | *None* | Executes the 5 attack scenarios from `simulator.py` and returns structured verdicts. |
| `GET` | `/sentinel/logs` | Query params: `level`, `limit` | Filterable security audit logs. |
| `GET` | `/sentinel/health` | *None* | Health status of SentinelLayer sub-detectors. |
| `GET` | `/docs` | *None* | Interactive OpenAPI Swagger UI documentation. |

---

## 6. Frontend Architecture & Dual-UI Rules

The entire frontend resides in a single, self-contained template file:  
`cinesage/templates/index.html`

### Strict Architecture Separation
To ensure both modules coexist without conflict, the DOM is partitioned into three distinct layers:

1. **Top-Level App Switcher (`#main-app-switcher`)**:
   - Fixed navigation bar at the top of `<body>`.
   - Toggle buttons:
     - `Prompt Injection (Entertainment)` $\rightarrow$ calls `switchApp('prompt')`
     - `VAPT Assessment (Education/Payment)` $\rightarrow$ calls `switchApp('vapt')`
2. **Prompt Injection Container (`#prompt-app-container`)**:
   - Wraps the original CineSage application.
   - **Theme & Aesthetics**: Dark Cyberpunk / Hacker style.
   - **Color Palette**: Background `#0a0e17`, cards `#111827`, border `#1e3a5f`, accents `#00ff88` (toxic green) and `#00d4ff` (cyan).
   - **Features**: Chat stream with live defense toggle, attack playbook sidebar (pre-built prompt injection scripts), Poison Lab (RAG injection tab), Model Probe (HuggingFace provenance tab), and Live Security Telemetry radar.
3. **VAPT Assessment Container (`#vapt-app-container`)**:
   - Completely independent DOM tree displayed when the VAPT tab is active.
   - **Theme & Aesthetics**: Professional Enterprise SaaS / Clean Light Theme.
   - **Color Palette**: Background `#f8fafc`, cards `#ffffff`, borders `#e2e8f0`, brand blue `#2563eb`, typography `#0f172a` / `#475569`.
   - **Features**:
     - Target URL input with domain context dropdown (`Education`, `Payment`, `Entertainment`).
     - Explicit authorization confirmation checkbox.
     - Real-time multi-phase assessment stepper (Phase 1 DNS Recon, Phase 2 Port Matrix, Phase 3 TLS Handshake, Phase 4 HTTP Headers, Phase 5 Threat Synthesis) with live terminal log stream.
     - Dynamic radial SVG security score gauge (color-coded: Green A+ ≥90, Blue B ≥70, Orange C ≥50, Red F <50).
     - Domain Compliance Radar (dynamically evaluating PCI-DSS v4.0 for Payment vs FERPA & student PII for Education).
     - Severity breakdown counters acting as interactive filter chips (Critical, High, Medium, Low, Informational).
     - Sticky category navigation (`All`, `Network & Ports`, `Transport & SSL`, `HTTP Security`, `Disclosure`) with keyword search.
     - 25-port network surface matrix grid (HTTP, HTTPS, SSH, MySQL, Postgres, Redis, RDP, etc.).
     - Authoritative DNS intelligence (A, MX, NS, TXT) and defensive HTTP response directives inspector.
     - Slide-over vulnerability inspection drawer presenting full attack scenarios, impact analysis, evidence, and remediation code snippets.
     - "Export Audit Report" JSON export for compliance records.

### Critical Frontend Switching Logic
```javascript
function switchApp(app) {
    const promptContainer = document.getElementById('prompt-app-container');
    const vaptContainer = document.getElementById('vapt-app-container');
    const btnPrompt = document.getElementById('btn-switch-prompt');
    const btnVapt = document.getElementById('btn-switch-vapt');
    const brandSub = document.getElementById('switcher-brand-sub');

    if (app === 'prompt') {
        promptContainer.style.display = 'flex';
        vaptContainer.style.display = 'none';
        btnPrompt.style.background = 'rgba(0, 255, 136, 0.12)';
        btnPrompt.style.borderColor = 'rgba(0, 255, 136, 0.35)';
        btnPrompt.style.color = '#00ff88';
        btnVapt.style.background = 'transparent';
        btnVapt.style.borderColor = 'transparent';
        btnVapt.style.color = '#94a3b8';
        document.body.style.background = '#0a0e17';
        if (brandSub) brandSub.textContent = 'OWASP LLM Security Demo · Entertainment';
    } else {
        promptContainer.style.display = 'none';
        vaptContainer.style.display = 'flex';
        btnPrompt.style.background = 'transparent';
        btnPrompt.style.borderColor = 'transparent';
        btnPrompt.style.color = '#94a3b8';
        btnVapt.style.background = '#2563eb';
        btnVapt.style.borderColor = '#2563eb';
        btnVapt.style.color = '#ffffff';
        document.body.style.background = '#f8fafc';
        if (brandSub) brandSub.textContent = 'Enterprise VAPT · Education & Payment';
    }
}
```

---

## 7. Strict Rules & Constraints for Future Agents

When modifying or extending this codebase, adhere to the following rules:

> [!CAUTION]
> ### RULE 1: Never Modify or Redesign the Prompt Injection UI
> - The CineSage Prompt Injection UI was intentionally designed with a dark, high-contrast cyber aesthetic.
> - **DO NOT** rewrite, restyle, refactor, or delete `#prompt-app-container` or its internal tabs, classes, or styles.
> - **DO NOT** attempt to "unify" the dark theme into the light theme or vice-versa. The dual-aesthetic separation is a mandatory project requirement.

> [!IMPORTANT]
> ### RULE 2: Maintain Clean Separation in `index.html`
> - Any modifications to the VAPT module must strictly reside within `#vapt-app-container` and its associated JavaScript functions (`startVaptScan`, `renderVaptResults`, `showVaptFinding`, `generateReport`).
> - Global CSS rules must not leak between containers. Keep container-specific styles scoped or inline.

> [!IMPORTANT]
> ### RULE 3: Keep VAPT Passive & Non-Destructive
> - The VAPT scanner is designed for safe assessment. It must never perform invasive exploitation, destructive SQL injection fuzzing, denial-of-service tests, or credential brute-forcing.
> - Always maintain the user authorization checkbox requirement before triggering network scans.

> [!NOTE]
> ### RULE 4: Preserve SentinelLayer Modularity
> - The `sentinel/` package must remain a standalone, decoupled library capable of being imported into any external FastAPI project.
> - Application-specific logic (such as CineSage movie RAG retrieval or VAPT scanning) belongs in `cinesage/`, never in `sentinel/`.

---

## 8. Operations & Quick-Start Runbook

### Prerequisites
- Python 3.10+ (tested on Python 3.11/3.12).
- Virtual environment activated (`venv`).

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```
*Note: Key packages are `fastapi`, `uvicorn[standard]`, `pydantic`, `httpx`, `dnspython`, `python-dotenv`.*

### 2. Launching the Main Application (CineSage + VAPT)
From the repository root:
```bash
python -m uvicorn cinesage.main:app --reload --port 8000
```
*Or via the helper script:*
```bash
python cinesage/run.py
```
*Access in browser:*  
Open `http://localhost:8000` to interact with both the Prompt Injection module and the VAPT Assessment module.

### 3. Launching Standalone SentinelLayer API (Optional)
```bash
python -m uvicorn app:app --reload --port 8765
```
*Swagger UI available at:* `http://localhost:8765/docs`

### 4. Running the Attack Simulator CLI
```bash
python simulator.py
```
*Executes all 5 OWASP threat scenarios headlessly and logs detection outputs.*

### 5. Running Verification Tests
```bash
python verify.py
```
*Validates that all detectors and pipeline components initialize and produce expected verdicts.*

---

## 9. Common Gotchas & Troubleshooting

1. **DNS Resolution Errors during VAPT**:
   - `dns.resolver.resolve` requires the target to be a resolvable domain name. If scanning an IP address directly or a non-existent domain, the scanner gracefully catches the exception and reports the DNS status.
2. **Port Scanning Timeouts**:
   - `check_port` uses a 1.0-second timeout per port. All 25 ports are scanned concurrently using `asyncio.gather()`, typically completing within 1.5 seconds.
3. **Groq API Key**:
   - If `GROQ_API_KEY` is not set in `.env`, CineSage automatically falls back to simulated responses without crashing.
4. **Sentence Transformers**:
   - `sentence-transformers` is optional. If not installed, `detector_prompt.py` falls back to regex and keyword heuristics seamlessly.
