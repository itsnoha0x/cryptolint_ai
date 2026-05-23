

https://github.com/user-attachments/assets/6034f9da-8082-423c-8f08-ddccdf20b547

# CryptoLint AI — Android Cryptographic Vulnerability Scanner

> Static analysis + LLM-powered risk reasoning for Android cryptographic misuse detection.  
> Accepts APK, Java, or Kotlin files. No build system required.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Model: Qwen2.5-Coder-32B](https://img.shields.io/badge/Model-Qwen2.5--Coder--32B-purple.svg)](https://featherless.ai)
[![Validated on: UnCrackable + AndroGoat](https://img.shields.io/badge/Validated%20on-UnCrackable%20%7C%20AndroGoat-green.svg)](https://github.com/OWASP/owasp-mastg)

---

## What it does

CryptoLint AI scans Android application code for cryptographic vulnerabilities using a two-layer approach:

1. **Static analysis engine** — 16 regex-based rules covering the most common cryptographic misuse patterns in Android Java/Kotlin code, each mapped to NIST SP 800-131A, OWASP Mobile Top 10, and CWE identifiers.
2. **LLM reasoning layer** — after static detection, the Qwen2.5-Coder-32B-Instruct model (via Featherless AI) produces a structured risk report with a global risk score (0–100), attack scenario narratives, compliance impact (GDPR, PCI-DSS), and on-demand annotated Java remediation patches.

Validated against **OWASP UnCrackable Level 1** and **AndroGoat** — correctly identifying all in-scope vulnerabilities with no false negatives for covered rule patterns.

---

## Project structure

```
cryptolint-ai/
├── backend/
│   ├── app.py                       # Flask API — static engine + LLM calls
│   └── requirements.txt             # Python dependencies
├── frontend/
│   └── index.html                   # Single-page UI (no build tools needed)
├── sample/
│   └── InsecureCryptoExample.java   # Test file with all 16 vulnerabilities
└── README.md
```

---

## Quick start

### Prerequisites

- Python 3.10+
- Java JDK 11+ (required by Jadx for APK decompilation)
- A [Featherless AI](https://featherless.ai) API key
 Alternatively, any OpenAI-compatible API endpoint works — just update `FEATHERLESS_BASE_URL` and `MODEL` in `app.py`.
- Jadx binary ([download here](https://github.com/skylot/jadx/releases))

### 1. Backend setup

```bash
cd backend

# Create and activate a virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

Create a `.env` file in the `backend/` directory:

```env
FEATHERLESS_API_KEY=your_api_key_here
JAVA_HOME=C:\Program Files\Java\jdk-21.x.x     # Windows example
# JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64  # Linux example
JADX_PATH=D:\tools\jadx\bin\jadx.bat            # Windows example
# JADX_PATH=/usr/local/bin/jadx                  # Linux/macOS example
```

```bash
# Start the backend
python app.py
# API is now running at http://localhost:5000
```

### 2. Frontend

Open `frontend/index.html` directly in your browser. No build step, no Node.js.

> If you hit CORS issues, serve it locally instead:
> ```bash
> cd frontend && python -m http.server 8080
> # Then open http://localhost:8080
> ```

---

## Detection rules

16 rules across 7 vulnerability categories. Each rule includes a severity level, CWE reference, description, and a remediation template used in fallback mode when the LLM API is unavailable.

| Rule ID | Category | Severity | Standard |
|---|---|---|---|
| `HASH_MD5` | Weak hash algorithm | 🔴 Critique | CWE-328, OWASP M5 |
| `HASH_SHA1` | Weak hash algorithm | 🔴 Critique | CWE-328, NIST SP 800-131A |
| `AES_ECB` | Insecure cipher mode | 🔴 Critique | CWE-327, NIST SP 800-38A |
| `AES_CBC_NOAUTH` | Unauthenticated cipher | 🟠 Majeur | CWE-327, CVE-2014-3566 |
| `DES_USAGE` | Deprecated algorithm | 🔴 Critique | CWE-326, NIST SP 800-131A |
| `HARDCODED_KEY` | Hardcoded key | 🔴 Critique | CWE-321, OWASP M1 |
| `STATIC_IV` | Static IV/nonce | 🔴 Critique | CWE-330, NIST SP 800-38D |
| `WEAK_RNG_RANDOM` | Weak PRNG | 🟠 Majeur | CWE-338, OWASP M5 |
| `MATH_RANDOM` | Weak PRNG | 🟠 Majeur | CWE-338 |
| `SHAREDPREFS_KEY` | Insecure key storage | 🔴 Critique | CWE-312, OWASP M2 |
| `INTERNAL_STORAGE_KEY` | World-readable file | 🟠 Majeur | CWE-732, OWASP M2 |
| `SSL_ALL_HOSTS` | TLS hostname bypass | 🔴 Critique | CWE-297, OWASP M3 |
| `TRUST_ALL_CERTS` | TrustManager bypass | 🔴 Critique | CWE-295, OWASP M3 |
| `HTTP_CLEAR_TEXT` | Cleartext HTTP | 🟠 Majeur | CWE-319, OWASP M3 |
| `PKCS5_PADDING` | Dangerous padding | 🟡 Mineur | CWE-649, CVE-2016-2183 |
| `RSA_SMALL_KEY` | RSA key < 2048 bits | 🟠 Majeur | CWE-326, NIST SP 800-57 |

> **Severity scale:** Critique = directly exploitable with public tooling / Majeur = significant risk in most threat models / Mineur = context-dependent, best-practice violation.

---

## LLM output

After static analysis, the tool calls the Qwen2.5-Coder-32B-Instruct model and returns a structured JSON risk report:

```json
{
  "global_risk_score": 85,
  "global_summary": "The application uses MD5 for password hashing and AES-ECB for encryption...",
  "attack_scenarios": [
    "An attacker with physical access can extract the APK and recover the hardcoded AES key using jadx in under 60 seconds.",
    "AES-ECB mode leaks plaintext patterns, enabling chosen-plaintext attacks on encrypted user data."
  ],
  "remediation_priority": "1. Replace hardcoded key with Android Keystore. 2. Switch to AES/GCM/NoPadding. 3. Replace MD5 with SHA-256.",
  "compliance_impact": "Non-compliant with OWASP M1, M5. GDPR Article 32 (appropriate technical measures). PCI-DSS Requirement 6.2.",
  "estimated_exploit_difficulty": "facile"
}
```

For any individual finding, `POST /api/patch/<rule_id>` returns a fully annotated Java patch with the corrected code, inline comments, and required Gradle dependencies.

---

## REST API reference

### `POST /api/analyze`

Accepts a file upload or a raw code payload.

**File upload:**
```bash
curl -X POST http://localhost:5000/api/analyze \
  -F "file=@sample/InsecureCryptoExample.java"
```

**APK upload:**
```bash
curl -X POST http://localhost:5000/api/analyze \
  -F "file=@app-release.apk"
```

**JSON code payload:**
```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "Cipher cipher = Cipher.getInstance(\"AES\");", "filename": "Test.java"}'
```

**Response:**
```json
{
  "success": true,
  "filename": "app-release.apk",
  "stats": {
    "total": 12,
    "critique": 7,
    "majeur": 4,
    "mineur": 1,
    "categories": ["Weak hash algorithm", "Insecure cipher mode", "..."],
    "lines_analyzed": 3842
  },
  "findings": [
    {
      "rule_id": "HASH_MD5",
      "severity": "critique",
      "title": "Utilisation de MD5",
      "file": "MainActivity.java",
      "line": 42,
      "matched_code": "MessageDigest.getInstance(\"MD5\")",
      "context": "41: byte[] hash =\n42: MessageDigest.getInstance(\"MD5\")\n43:   .digest(data);",
      "description": "MD5 is cryptographically broken...",
      "fix": "MessageDigest.getInstance(\"SHA-256\")",
      "reference": "OWASP Mobile M5, CWE-328"
    }
  ],
  "ai_analysis": { "global_risk_score": 85, "..." : "..." }
}
```

### `POST /api/patch/<rule_id>`

Generates an annotated Java remediation patch for a specific finding.

```bash
curl -X POST http://localhost:5000/api/patch/HARDCODED_KEY \
  -H "Content-Type: application/json" \
  -d '{"finding": {"rule_id": "HARDCODED_KEY", "matched_code": "new SecretKeySpec(\"key\".getBytes(), \"AES\")", "...": "..."}}'
```

**Response:**
```json
{
  "vulnerable_code": "new SecretKeySpec(\"MyS3cr3tK3y\".getBytes(), \"AES\")",
  "patched_code": "// Use Android Keystore — key is hardware-backed, never in bytecode\nKeyStore ks = KeyStore.getInstance(\"AndroidKeyStore\");\n...",
  "explanation": "Hardcoded keys are extractable from APK bytecode in seconds using jadx.",
  "libs_needed": ["androidx.security:security-crypto:1.1.0-alpha06"]
}
```

### `GET /api/rules`

Returns the full catalog of 16 detection rules.

### `GET /api/health`

Returns service status, active model name, and rule count.

---

## CI/CD integration

Use CryptoLint AI as a security gate in your Android build pipeline. The example below fails the build if any critical cryptographic vulnerability is found in the release APK.

```bash
# GitHub Actions / Jenkins pipeline step
RESULT=$(curl -s -X POST http://localhost:5000/api/analyze \
  -F "file=@app/build/outputs/apk/release/app-release.apk")

CRITIQUES=$(echo $RESULT | python3 -c \
  "import sys, json; print(json.load(sys.stdin)['stats']['critique'])")

if [ "$CRITIQUES" -gt "0" ]; then
  echo "SECURITY GATE FAILED: $CRITIQUES critical crypto vulnerabilities detected."
  exit 1
fi
echo "Cryptographic security gate passed."
```

For a more granular gate, you can also check `majeur` count or specific rule IDs from the `findings` array.

---

## Cryptographic quick-reference

Common Android cryptographic mistakes and their correct replacements:

| Vulnerable pattern | Secure alternative |
|---|---|
| `MessageDigest.getInstance("MD5")` | `MessageDigest.getInstance("SHA-256")` |
| `MessageDigest.getInstance("SHA-1")` | `MessageDigest.getInstance("SHA-3-256")` |
| `Cipher.getInstance("AES")` | `Cipher.getInstance("AES/GCM/NoPadding")` |
| `Cipher.getInstance("AES/CBC/...")` | `Cipher.getInstance("AES/GCM/NoPadding")` |
| `Cipher.getInstance("DES/...")` | `Cipher.getInstance("AES/GCM/NoPadding")` |
| `new SecretKeySpec("hardcoded".getBytes(), "AES")` | Android Keystore System |
| `new IvParameterSpec(new byte[]{0,0,...})` | `SecureRandom().nextBytes(iv)` |
| `new Random()` | `new SecureRandom()` |
| `Math.random()` | `SecureRandom().nextDouble()` |
| `getSharedPreferences(...)` for secrets | `EncryptedSharedPreferences` (Jetpack Security) |
| `ALLOW_ALL_HOSTNAME_VERIFIER` | Default `HttpsURLConnection` verifier |
| Custom empty `X509TrustManager` | Certificate Pinning via OkHttp `CertificatePinner` |
| `http://` URLs | `https://` + `network_security_config.xml` |
| `KeyPairGenerator.initialize(1024)` | `KeyPairGenerator.initialize(4096)` or ECDSA P-256 |

---

## Limitations

- **Dynamic algorithm parameters** — if the algorithm name is constructed at runtime (e.g. `Cipher.getInstance(getAlgo())`), the regex engine cannot detect it. Dataflow-based taint analysis is planned for a future version.
- **Library filter coverage** — the path-based library filter covers major Android namespaces (`/androidx`, `/kotlin`, `/google`, `/okhttp`, `/okio`). Third-party libraries in non-standard package paths may produce occasional false positives.
- **Decompilation fidelity** — heavily obfuscated APKs may produce incomplete Java source from Jadx, reducing detection coverage. Smali bytecode analysis support is planned.

---

## Validation

CryptoLint AI was tested against two publicly available, deliberately vulnerable Android benchmarks:

- **[OWASP UnCrackable Level 1](https://github.com/OWASP/owasp-mastg/tree/master/Crackmes)** — detected `HARDCODED_KEY` and `AES_ECB` in the decompiled source. AI risk score: 85/100.
- **[AndroGoat](https://github.com/satishpatnayak/AndroGoat)** — detected `HASH_MD5`, `AES_ECB`, `HARDCODED_KEY`, `STATIC_IV`, `SSL_ALL_HOSTS`, and `TRUST_ALL_CERTS` across six cryptographic test cases. No false negatives for in-scope rule patterns.

---

## References

- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [NIST SP 800-131A — Transitioning Cryptographic Algorithms](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [NIST SP 800-38D — GCM Mode](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [CWE-310 Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)
- [Jadx — Dex to Java decompiler](https://github.com/skylot/jadx)
- [Featherless AI](https://featherless.ai)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
