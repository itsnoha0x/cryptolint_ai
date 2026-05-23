"""
CryptoLint AI - Backend Flask API
Analyse statique des mauvaises pratiques crypto dans le code Android
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import zipfile
import tempfile
import shutil
import re
import json
import subprocess
import requests
from pathlib import Path

# Optional: Load variables from .env file if it exists
# On force le chemin absolu vers le .env pour eviter les erreurs de dossier courant
from dotenv import load_dotenv
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path, override=True)

app = Flask(__name__)
CORS(app)

# ─── Configuration Featherless AI ────────────────────────────────────────────
FEATHERLESS_API_KEY = os.environ.get("FEATHERLESS_API_KEY")
FEATHERLESS_BASE_URL = "https://api.featherless.ai/v1"
MODEL = "Qwen/Qwen2.5-Coder-32B-Instruct"

# Configuration Jadx (Peut être surchargé dans .env via JADX_PATH)
JADX_BIN = os.environ.get("JADX_PATH", "jadx.bat" if os.name == "nt" else "jadx")

if not FEATHERLESS_API_KEY:
    print("⚠️  Warning: FEATHERLESS_API_KEY is not set. AI features will use fallback mock data.")
    print("   Please set it in a .env file or as an environment variable.")

def get_safe_env():
    """Crée un environnement qui priorise JAVA_HOME/bin pour éviter les conflits (.js)"""
    env = os.environ.copy()
    java_home = env.get("JAVA_HOME", "").strip()
    if java_home:
        # S'assurer que le chemin est propre (sans guillemets ou espaces superflus)
        java_home = java_home.strip('"').strip("'")
        env["JAVA_HOME"] = java_home
        java_bin = os.path.join(java_home, "bin")
        # On place le bin de Java tout au début du PATH pour ce processus
        env["PATH"] = java_bin + os.pathsep + env.get("PATH", "")
    return env

def check_dependencies():
    """Vérifie si Java et Jadx sont accessibles au démarrage"""
    print("🔍 Checking system dependencies...")
    safe_env = get_safe_env()
    java_home = safe_env.get("JAVA_HOME", "").strip()

    if java_home:
        print(f"  ℹ️  JAVA_HOME is set to: {java_home}")
        # Vérification physique
        java_exe = os.path.join(java_home, "bin", "java.exe" if os.name == "nt" else "java")
        if not os.path.exists(java_exe):
            print(f"  ❌ ERROR: java.exe NOT found at: {java_exe}")
            print(f"     Le dossier 'bin' est-il bien dans '{java_home}' ?")
            
            # Aide au diagnostic : on liste les dossiers parents si on ne trouve pas
            parent = os.path.dirname(java_home)
            if os.path.exists(parent):
                print(f"     Dossiers trouvés dans {parent} :")
                for d in os.listdir(parent):
                    if os.path.isdir(os.path.join(parent, d)):
                        print(f"       - {d}")

    # On cherche le chemin réel utilisé par le système pour 'java'
    # On cherche d'abord dans notre environnement modifié
    java_path = shutil.which("java", path=safe_env.get("PATH"))
    
    try:
        if java_path:
            print(f"  ✅ Java executable found at: {java_path}")
            if java_path.lower().endswith(".js"):
                print("  ❌ CRITICAL: System is STILL picking up a JavaScript file!")
            else:
                print("  ✨ Java path is healthy (pointing to .exe)")
        else:
            print("  ✅ Java found")
    except Exception:
        print(f"  ❌ Java is NOT functional. Path found: {java_path or 'None'}")

    try:
        # Test simple de jadx
        subprocess.run([JADX_BIN, "--version"], capture_output=True, check=True, shell=os.name=="nt", env=safe_env)
        print(f"  ✅ Jadx is functional ({JADX_BIN})")
    except Exception:
        print(f"  ❌ Jadx is NOT functional at: {JADX_BIN}")
    print("-----------------------------------")

# ─── Règles de détection statique ────────────────────────────────────────────
CRYPTO_RULES = [
    # ── Algorithmes de hachage faibles ──
    {
        "id": "HASH_MD5",
        "severity": "critique",
        "category": "Hachage faible",
        "pattern": r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']\s*\)',
        "title": "Utilisation de MD5",
        "description": "MD5 est cryptographiquement cassé depuis 2004. Des collisions peuvent être générées en quelques secondes.",
        "fix": 'MessageDigest.getInstance("SHA-256")',
        "reference": "OWASP Mobile M5, CWE-328",
    },
    {
        "id": "HASH_SHA1",
        "severity": "critique",
        "category": "Hachage faible",
        "pattern": r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']\s*\)',
        "title": "Utilisation de SHA-1",
        "description": "SHA-1 est vulnérable aux attaques par collision (SHAttered 2017). Non conforme PCI-DSS et NIST depuis 2015.",
        "fix": 'MessageDigest.getInstance("SHA-256") // ou SHA-3',
        "reference": "OWASP Mobile M5, CWE-328, NIST SP 800-131A",
    },
    # ── Modes de chiffrement dangereux ──
    {
        "id": "AES_ECB",
        "severity": "critique",
        "category": "Mode de chiffrement non sécurisé",
        "pattern": r'Cipher\.getInstance\s*\(\s*["\']AES["\']',
        "title": "AES sans mode spécifié (ECB par défaut)",
        "description": "AES sans mode utilise ECB par défaut. ECB ne fournit aucune confidentialité sémantique : blocs identiques → texte chiffré identique.",
        "fix": 'Cipher.getInstance("AES/GCM/NoPadding") // Authentifié + IND-CPA',
        "reference": "CWE-327, NIST SP 800-38A",
    },
    {
        "id": "AES_CBC_NOAUTH",
        "severity": "majeur",
        "category": "Mode de chiffrement non authentifié",
        "pattern": r'Cipher\.getInstance\s*\(\s*["\']AES/CBC',
        "title": "AES-CBC sans authentification",
        "description": "AES-CBC est vulnérable aux attaques padding oracle (POODLE, BEAST) et ne garantit pas l'intégrité des données.",
        "fix": 'Cipher.getInstance("AES/GCM/NoPadding") // AEAD : confidentialité + intégrité',
        "reference": "CWE-327, CVE-2014-3566",
    },
    {
        "id": "DES_USAGE",
        "severity": "critique",
        "category": "Algorithme obsolète",
        "pattern": r'Cipher\.getInstance\s*\(\s*["\']DES',
        "title": "Utilisation de DES/3DES",
        "description": "DES (56 bits) est cassable par brute force en moins de 24h. 3DES est également déprécié (Sweet32 attack).",
        "fix": 'Cipher.getInstance("AES/GCM/NoPadding") // AES-256',
        "reference": "CWE-326, NIST SP 800-131A Rev2",
    },
    # ── Clés statiques / hardcodées ──
    {
        "id": "HARDCODED_KEY",
        "severity": "critique",
        "category": "Clé hardcodée",
        "pattern": r'(?:SecretKeySpec|SecretKey)\s*\(.*?["\'][A-Za-z0-9+/=]{8,}["\']',
        "title": "Clé cryptographique hardcodée dans le code",
        "description": "Les clés statiques dans le bytecode sont extractibles via reverse engineering (jadx, apktool). Compromet tout le système.",
        "fix": "// Utiliser Android Keystore System\nKeyStore ks = KeyStore.getInstance(\"AndroidKeyStore\");\nKeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, \"AndroidKeyStore\");",
        "reference": "OWASP Mobile M1, CWE-321",
    },
    {
        "id": "STATIC_IV",
        "severity": "critique",
        "category": "IV/Nonce statique",
        "pattern": r'(?:IvParameterSpec|GCMParameterSpec)\s*\(\s*new\s+byte\s*\[\s*\{[^}]*\}\s*\]',
        "title": "IV/Nonce statique ou prédictible",
        "description": "Un IV fixe avec la même clé rend le chiffrement déterministe. Pour AES-GCM, réutiliser un nonce avec la même clé est catastrophique (key recovery possible).",
        "fix": "byte[] iv = new byte[12];\nnew SecureRandom().nextBytes(iv);\nnew GCMParameterSpec(128, iv);",
        "reference": "CWE-330, NIST SP 800-38D §8.3",
    },
    # ── Générateurs aléatoires faibles ──
    {
        "id": "WEAK_RNG_RANDOM",
        "severity": "majeur",
        "category": "RNG cryptographiquement faible",
        "pattern": r'\bnew\s+Random\s*\(',
        "title": "Utilisation de java.util.Random pour usage crypto",
        "description": "java.util.Random est un PRNG linéaire congruentiel, prédictible. Ne jamais l'utiliser pour générer des clés, tokens ou IVs.",
        "fix": "SecureRandom sr = new SecureRandom();\nbyte[] key = new byte[32];\nsr.nextBytes(key);",
        "reference": "CWE-338, OWASP Mobile M5",
    },
    {
        "id": "MATH_RANDOM",
        "severity": "majeur",
        "category": "RNG cryptographiquement faible",
        "pattern": r'Math\.random\s*\(',
        "title": "Utilisation de Math.random() pour usage crypto",
        "description": "Math.random() n'est pas conçu pour la cryptographie. Sortie prédictible après observation de quelques valeurs.",
        "fix": "SecureRandom sr = new SecureRandom();\ndouble rand = sr.nextDouble();",
        "reference": "CWE-338",
    },
    # ── Stockage clés non sécurisé ──
    {
        "id": "SHAREDPREFS_KEY",
        "severity": "critique",
        "category": "Stockage de clé non sécurisé",
        "pattern": r'getSharedPreferences.*?(?:key|secret|password|token|crypto)',
        "title": "Clé/secret stocké en SharedPreferences",
        "description": "SharedPreferences est non chiffré et accessible sur device rooté. Tout secret stocké ici est exposé.",
        "fix": "// Utiliser EncryptedSharedPreferences (Jetpack Security)\nEncryptedSharedPreferences.create(\n    \"secret_prefs\",\n    masterKeyAlias,\n    context,\n    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,\n    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM\n);",
        "reference": "OWASP Mobile M2, CWE-312",
    },
    {
        "id": "INTERNAL_STORAGE_KEY",
        "severity": "majeur",
        "category": "Stockage de clé non sécurisé",
        "pattern": r'openFileOutput.*?(?:MODE_WORLD|0777|0666)',
        "title": "Fichier de clé avec permissions world-readable",
        "description": "Fichier accessible par d'autres applications ou via backup ADB non chiffré.",
        "fix": "// Mode privé uniquement\nopenFileOutput(filename, Context.MODE_PRIVATE)\n// + chiffrement via Android Keystore",
        "reference": "CWE-732, OWASP Mobile M2",
    },
    # ── Configuration TLS ──
    {
        "id": "SSL_ALL_HOSTS",
        "severity": "critique",
        "category": "TLS/SSL mal configuré",
        "pattern": r'(?:setHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier)',
        "title": "Vérification du hostname TLS désactivée",
        "description": "Désactiver la vérification du hostname rend l'application vulnérable aux attaques MITM. N'importe quel certificat valide sera accepté.",
        "fix": "// Ne JAMAIS désactiver la vérification hostname\n// Utiliser le vérificateur par défaut\nHttpsURLConnection.getDefaultHostnameVerifier()",
        "reference": "CWE-297, OWASP Mobile M3",
    },
    {
        "id": "TRUST_ALL_CERTS",
        "severity": "critique",
        "category": "TLS/SSL mal configuré",
        "pattern": r'(?:TrustAllCerts|X509TrustManager.*?checkServerTrusted.*?\{\s*\}|insecure)',
        "title": "TrustManager acceptant tous les certificats",
        "description": "Un TrustManager vide accepte n'importe quel certificat SSL/TLS, permettant des attaques MITM complètes.",
        "fix": "// Utiliser Certificate Pinning\nCertificatePinner pinner = new CertificatePinner.Builder()\n    .add(\"api.example.com\", \"sha256/AAAAAAA...\")\n    .build();\nnew OkHttpClient.Builder().certificatePinner(pinner).build();",
        "reference": "CWE-295, OWASP Mobile M3",
    },
    {
        "id": "HTTP_CLEAR_TEXT",
        "severity": "majeur",
        "category": "Communication non chiffrée",
        "pattern": r'http://(?!localhost|127\.0\.0\.1|10\.|192\.168)',
        "title": "URL HTTP en clair (non HTTPS)",
        "description": "Communications non chiffrées exposent les données à l'écoute passive. Android 9+ bloque le trafic clair par défaut.",
        "fix": "// Remplacer par HTTPS\nhttps://api.example.com/endpoint\n// + network_security_config.xml avec cleartextTrafficPermitted=\"false\"",
        "reference": "CWE-319, OWASP Mobile M3",
    },
    # ── Padding Oracle ──
    {
        "id": "PKCS5_PADDING",
        "severity": "mineur",
        "category": "Padding potentiellement dangereux",
        "pattern": r'(?:PKCS5Padding|PKCS7Padding)',
        "title": "Padding PKCS#5/7 avec mode non-AEAD",
        "description": "PKCS#5/7 padding combiné avec CBC est vulnérable aux attaques padding oracle si les erreurs ne sont pas gérées en temps constant.",
        "fix": "// Préférer AES/GCM/NoPadding (pas de padding nécessaire)\nCipher.getInstance(\"AES/GCM/NoPadding\")",
        "reference": "CWE-649, CVE-2016-2183 (SWEET32)",
    },
    # ── Clés de taille insuffisante ──
    {
        "id": "RSA_SMALL_KEY",
        "severity": "majeur",
        "category": "Taille de clé insuffisante",
        "pattern": r'KeyPairGenerator.*?initialize\s*\(\s*(?:512|768|1024)\s*\)',
        "title": "Clé RSA de taille insuffisante (< 2048 bits)",
        "description": "RSA-1024 est cassable avec des ressources modestes. NIST recommande minimum 2048 bits jusqu'en 2030.",
        "fix": "keyPairGenerator.initialize(4096); // ou 3072 minimum\n// Pour IoT contraint : utiliser ECDSA P-256 (équivalent RSA-3072)",
        "reference": "CWE-326, NIST SP 800-57",
    },
]


def analyze_code_static(code: str, filename: str = "unknown.java") -> list[dict]:
    """Analyse statique du code contre les règles CRYPTO_RULES"""
    findings = []

    for rule in CRYPTO_RULES:
        try:
            matches = list(re.finditer(rule["pattern"], code, re.IGNORECASE | re.DOTALL))
        except re.error:
            continue

        for match in matches:
            # Numéro de ligne
            line_num = code[:match.start()].count('\n') + 1
            # Contexte : 2 lignes avant/après
            lines = code.split('\n')
            start = max(0, line_num - 3)
            end = min(len(lines), line_num + 2)
            context = '\n'.join(f"{start+i+1}: {lines[start+i]}" for i in range(end - start))

            findings.append({
                "rule_id": rule["id"],
                "severity": rule["severity"],
                "category": rule["category"],
                "title": rule["title"],
                "description": rule["description"],
                "fix": rule["fix"],
                "reference": rule["reference"],
                "file": filename,
                "line": line_num,
                "matched_code": match.group(0)[:200],
                "context": context,
                "ai_analysis": None,  # Rempli après
            })
            
    if findings:
        print(f"  🔍 {len(findings)} vulnérabilités potentielles trouvées par scan statique.")

    return findings


def call_featherless_ai(findings: list[dict], code_snippet: str) -> str:
    """Appel à l'API Featherless AI (Qwen Coder) pour le risk reasoning"""
    if not findings:
        return "Aucune vulnérabilité détectée. Le code semble respecter les bonnes pratiques cryptographiques."

    findings_summary = "\n".join([
        f"- [{f['severity'].upper()}] {f['title']} (ligne {f['line']}): {f['description']}"
        for f in findings[:10]  # Max 10 pour le contexte
    ])

    prompt = f"""Tu es un expert en sécurité mobile Android spécialisé en cryptographie.

Voici les vulnérabilités cryptographiques détectées dans le code Android analysé :

{findings_summary}

Extrait de code analysé :
```java
{code_snippet[:3000]}
```

Pour chaque vulnérabilité, fournis une analyse de risque structurée en JSON avec ce format exact :
{{
  "global_risk_score": <0-100>,
  "global_summary": "<résumé exécutif en 2-3 phrases>",
  "attack_scenarios": ["<scénario 1>", "<scénario 2>"],
  "remediation_priority": "<ordre de priorité de correction>",
  "compliance_impact": "<impact OWASP Mobile Top 10, GDPR, PCI-DSS>",
  "estimated_exploit_difficulty": "<facile|moyen|difficile>"
}}

Réponds UNIQUEMENT avec le JSON valide, sans markdown, sans explication."""

    try:
        print(f"--- Calling Featherless AI ({MODEL}) for Risk Analysis ---")
        response = requests.post(
            f"{FEATHERLESS_BASE_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {FEATHERLESS_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": MODEL,
                "messages": [
                    {
                        "role": "system",
                        "content": "Tu es un expert sécurité Android. Analyse les vulnérabilités crypto et réponds en JSON valide uniquement."
                    },
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 8192,
                "temperature": 0.1,
            },
            timeout=60,
        )

        if response.status_code != 200:
            print(f"❌ API Error ({response.status_code}): {response.text}")

        data = response.json()
        content = data["choices"][0]["message"]["content"].strip()
        # Nettoyage markdown
        content = re.sub(r'```(?:json)?\s*|\s*```', '', content).strip()
        parsed = json.loads(content)
        parsed["ai_source"] = "featherless_ai"
        return json.dumps(parsed)
    except Exception as e:
        print(f"❌ ERREUR IA DÉTAILLÉE : {str(e)}")
        return json.dumps({
            "global_risk_score": 75,
            "global_summary": f"Analyse IA temporairement indisponible. {len(findings)} vulnérabilités détectées par analyse statique.",
            "attack_scenarios": ["Extraction de clés par reverse engineering", "Attaque MITM via TLS mal configuré"],
            "remediation_priority": "Corriger en priorité les vulnérabilités CRITIQUE",
            "compliance_impact": "Non conforme OWASP Mobile Top 10",
            "estimated_exploit_difficulty": "facile",
            "error": str(e),
            "ai_source": "fallback_mock_data"
        })


def call_ai_patch_suggestion(finding: dict) -> dict:
    """Génère un patch détaillé via IA pour une vulnérabilité spécifique"""
    prompt = f"""Vulnérabilité Android détectée :
Titre : {finding['title']}
Sévérité : {finding['severity']}
Code vulnérable : {finding['matched_code']}
Description : {finding['description']}

Génère un patch Java Android complet et commenté. Réponds en JSON :
{{
  "vulnerable_code": "<code vulnérable simplifié>",
  "patched_code": "<code corrigé complet avec commentaires>",
  "explanation": "<explication technique courte>",
  "libs_needed": ["<dépendance gradle si nécessaire>"]
}}
Réponds UNIQUEMENT en JSON valide."""

    try:
        print(f"--- Calling Featherless AI ({MODEL}) for Patch Generation ---")
        response = requests.post(
            f"{FEATHERLESS_BASE_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {FEATHERLESS_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 800,
                "temperature": 0.1,
            },
            timeout=60,
        )

        if response.status_code != 200:
            print(f"❌ API Error ({response.status_code}): {response.text}")

        data = response.json()
        content = data["choices"][0]["message"]["content"].strip()
        content = re.sub(r'```(?:json)?\s*|\s*```', '', content).strip()
        return json.loads(content)
    except Exception as e:
        print(f"❌ ERREUR IA DÉTAILLÉE : {str(e)}")
        return {
            "vulnerable_code": finding["matched_code"],
            "patched_code": finding["fix"],
            "explanation": finding["description"],
            "libs_needed": []
        }


# ─── Routes API ───────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    """Root route to confirm the API is up"""
    return jsonify({
        "status": "online",
        "name": "CryptoLint AI API",
        "usage": "Use /api/analyze to start an audit or open the frontend/index.html"
    })

@app.route("/api/analyze", methods=["POST"])
def analyze():
    """Endpoint principal d'analyse"""
    code_text = None
    filename = "code.java"

    if "file" in request.files:
        f = request.files["file"]
        filename = f.filename or "upload"

        if filename.endswith(".apk"):
            # Use TemporaryDirectory to prevent memory leaks if the process crashes
            with tempfile.TemporaryDirectory() as tmp_dir:
                apk_path = os.path.join(tmp_dir, "app.apk")
                f.save(apk_path)
                
                extract_dir = os.path.join(tmp_dir, "decompiled")
                
                try:
                    print("--- Running Jadx to decompile APK ---")
                    # On utilise JADX_BIN et get_safe_env() pour garantir que Java est bien trouvé
                    result = subprocess.run(
                        [JADX_BIN, "-d", extract_dir, "--no-res", "-j", "2", apk_path],
                        check=False,
                        capture_output=True,
                        shell=True if os.name == "nt" else False,
                        env=get_safe_env(),
                        text=True
                    )

                    if result.returncode != 0:
                        print(f"⚠️ Jadx a fini avec des erreurs partielles (code {result.returncode}). On tente de continuer l'analyse.")
                    
                    code_text = ""
                    file_count = 0
                    
                    # Walk through the decompiled directory to read .java files
                    for root, dirs, files in os.walk(extract_dir):
                        # CRITICAL FIX: Skip standard heavy libraries to save RAM and CPU
                        normalized_root = root.replace("\\", "/")
                        if any(lib in normalized_root for lib in ["/androidx", "/android/", "/kotlin", "/google", "/okhttp", "/okio"]):
                            continue
                            
                        for file in files:
                            if file.endswith(".java"):
                                file_path = os.path.join(root, file)
                                with open(file_path, "r", encoding="utf-8", errors="replace") as jf:
                                    code_text += f"\n// === {file} ===\n"
                                    code_text += jf.read()
                                    file_count += 1
                                    
                    if not code_text:
                        return jsonify({"error": "Décompilation réussie, mais aucun code source métier (hors librairies) trouvé."}), 400
                        
                    print(f"--- Successfully decompiled and filtered {file_count} Java files ---")

                except Exception as e:
                    return jsonify({"error": f"Erreur système lors du traitement de l'APK: {str(e)}"}), 500

        else:
            # Fichier Java/Kotlin
            code_text = f.read().decode('utf-8', errors='replace')

    elif request.is_json:
        data = request.get_json()
        code_text = data.get("code", "")
        filename = data.get("filename", "code.java")
    else:
        return jsonify({"error": "Fournissez un fichier APK, Java, ou du code JSON"}), 400

    if not code_text or len(code_text.strip()) < 10:
        return jsonify({"error": "Code trop court ou vide"}), 400

    # ── Analyse statique ──
    findings = analyze_code_static(code_text, filename)

    # ── Analyse IA globale ──
    # On passe de 2000 à 15000 caractères pour donner plus de contexte à l'IA
    ai_raw = call_featherless_ai(findings, code_text[:15000])
    try:
        ai_analysis = json.loads(ai_raw)
    except Exception:
        ai_analysis = {"global_summary": ai_raw, "global_risk_score": 50}

    # ── Statistiques ──
    stats = {
        "total": len(findings),
        "critique": sum(1 for f in findings if f["severity"] == "critique"),
        "majeur": sum(1 for f in findings if f["severity"] == "majeur"),
        "mineur": sum(1 for f in findings if f["severity"] == "mineur"),
        "categories": list(set(f["category"] for f in findings)),
        "files_analyzed": [filename],
        "lines_analyzed": code_text.count('\n') + 1,
    }

    return jsonify({
        "success": True,
        "filename": filename,
        "stats": stats,
        "findings": findings,
        "ai_analysis": ai_analysis,
    })


@app.route("/api/patch/<rule_id>", methods=["POST"])
def get_patch(rule_id):
    """Génère un patch IA pour une règle spécifique"""
    data = request.get_json()
    finding = data.get("finding", {})
    patch = call_ai_patch_suggestion(finding)
    return jsonify(patch)


@app.route("/api/rules", methods=["GET"])
def get_rules():
    """Retourne la liste des règles disponibles"""
    rules_summary = [{
        "id": r["id"],
        "severity": r["severity"],
        "category": r["category"],
        "title": r["title"],
        "reference": r["reference"],
    } for r in CRYPTO_RULES]
    return jsonify({"rules": rules_summary, "total": len(CRYPTO_RULES)})


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model": MODEL, "rules_count": len(CRYPTO_RULES)})


if __name__ == "__main__":
    check_dependencies()
    app.run(debug=True, host="0.0.0.0", port=5000)
