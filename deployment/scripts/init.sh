#!/usr/bin/env sh
set -eu

echo "============================================"
echo "      vt tool – CHECKLIST"
echo "============================================"

# -------------------------------------------------
# 1. Required binaries
# -------------------------------------------------
echo "[1/5] Checking required binaries..."

# Check for docker binary
if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: Missing required binary: docker"
fi

# Check that docker supports the compose subcommand
if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: Docker Compose is not available (docker compose subcommand required)"
fi

# Check curl
if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: Missing required binary: curl"
fi

echo "→ OK"

# -------------------------------------------------
# 2. Ensure .env exists
# -------------------------------------------------
echo "[2/5] Checking .env..."

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "→ .env created from .env.example"
    else
        echo "ERROR: Missing both .env and .env.example"
    fi
else
    echo "→ .env present"
fi

# Load environment variables
set -a
. ./.env
set +a

# -------------------------------------------------
# 3. Directory structure check
# -------------------------------------------------
echo "[3/5] Checking directory structure..."

DIRS=(
    "${MISP_PATH}"
)

for dir in "${DIRS[@]}"; do
    if [ -d "$dir" ]; then
        perms=$(stat -c '%a' "$dir")
        echo "→ Directory exists: $dir (permissions: $perms)"
    else
        echo "→ Directory missing: $dir"
    fi
done

echo "→ Directory structure check complete"

# -------------------------------------------------
# 4. Check misp ENV
# -------------------------------------------------
echo "[4/5] Checking application configuration..."

# MISP .env
if [ ! -f "${MISP_PATH}/.env" ]; then
    if [ -f "${MISP_PATH}/.env.example" ]; then
        cp "${MISP_PATH}/.env.example" "${MISP_PATH}/.env"
        echo "→ .env created from .env.example in MISP path"
    else
        echo "ERROR: Missing both .env and .env.example in MISP path"
    fi
else
    echo "→ .env present"
fi

# -------------------------------------------------
# 5. Certificates
# -------------------------------------------------
echo "[5/5] Checking certificates..."
CERTFILE="$CA_PATH/certfile.pem"
KEYFILE="$CA_PATH/keyfile.pem"
ROOTCAFILE="$CA_PATH/rootcafile.pem"

if [ ! -f "$CERTFILE" ] || [ ! -f "$KEYFILE" ] || [ ! -f "$ROOTCAFILE" ]; then
    echo "→ Missing certificates, generating..."
    ./scripts/openssl-certificates-generator.sh default --force
    mv ./certificates/default/certfile.pem "$CERTFILE"
    mv ./certificates/default/keyfile.pem "$KEYFILE"
    mv ./certificates/default/rootcafile.pem "$ROOTCAFILE"
    echo "→ Certificates generated in $CA_PATH"
else
    echo "→ Certificates already present"
fi

# -------------------------------------------------
# Completion
# -------------------------------------------------
echo "============================================"
echo "    CHECKLIST COMPLETED"
echo "    All required components are in place."
echo "    You can now modify:"
echo "        - ${MISP_PATH}/.env for MISP configuration"
echo "        - .env for network and other settings"
echo "    Then run 'make deploy' to start the application."
echo "============================================"
