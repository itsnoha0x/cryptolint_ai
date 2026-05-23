@echo off
echo 🔐 CryptoLint AI - Demarrage Windows
echo -----------------------------------

cd backend

if not exist venv (
    echo 📦 Creation de l'environnement virtuel...
    python -m venv venv
)

echo 🔌 Activation de l'environnement...
call venv\Scripts\activate

echo 📥 Installation/Verification des dependances...
pip install -r requirements.txt -q

echo 🚀 Lancement du serveur...
echo 🌐 Le backend sera sur http://localhost:5000
echo 📋 Ouvrez frontend\index.html dans votre navigateur
echo -----------------------------------

python app.py
pause