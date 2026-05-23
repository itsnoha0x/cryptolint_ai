#!/bin/bash
# ─── CryptoLint AI — Script de démarrage ───────────────────────────────────

set -e

echo ""
echo "🔐 CryptoLint AI — Démarrage"
echo "─────────────────────────────"

# Vérifier Python
if ! command -v python3 &>/dev/null; then
    echo "❌ Python 3 requis. Installez-le depuis https://python.org"
    exit 1
fi

# Se placer dans le backend
cd "$(dirname "$0")/backend"

# Créer venv si absent
if [ ! -d "venv" ]; then
    echo "📦 Création de l'environnement virtuel..."
    python3 -m venv venv
fi

# Activer le venv
source venv/bin/activate

# Installer les dépendances
echo "📥 Installation des dépendances..."
pip install -r requirements.txt -q

# Vérifier la clé API
if [ -z "$FEATHERLESS_API_KEY" ]; then
    echo ""
    echo "⚠️  FEATHERLESS_API_KEY non définie."
    echo "   L'analyse IA utilisera un fallback sans clé valide."
    echo "   Définissez-la avec : export FEATHERLESS_API_KEY='votre_cle'"
    echo ""
fi

echo ""
echo "🚀 Lancement du serveur Flask sur http://localhost:5000"
echo "🌐 Ouvrez frontend/index.html dans votre navigateur"
echo "📋 Ou lancez : python -m http.server 8080 dans /frontend"
echo ""
echo "Appuyez sur Ctrl+C pour arrêter."
echo "─────────────────────────────"
echo ""

python app.py
