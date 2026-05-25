#!/bin/bash
set -e

VERSION=$(node -p "require('./package.json').version")
TAG="v$VERSION"

echo ""
echo "  Dotward $TAG — Release Script"
echo "  ─────────────────────────────────────────"
echo ""

# ── Step 1: PyInstaller ────────────────────────────────────────────────────
echo "  [1/4] Building Flask server binary..."
source venv/bin/activate
pyinstaller dotward_macos_arm64.spec --noconfirm --log-level WARN
echo "        ✓ Binary built"

# ── Step 2: Electron Builder ───────────────────────────────────────────────
echo ""
echo "  [2/4] Building macOS DMG..."
npx electron-builder --mac --publish never 2>&1 | grep -E "•|building|error" | sed 's/^/        /'
echo "        ✓ DMG built"

# ── Step 3: GitHub Release ─────────────────────────────────────────────────
echo ""
echo "  [3/4] Creating GitHub release $TAG..."
gh release delete $TAG --yes 2>/dev/null || true
gh release create $TAG \
  --title "Dotward $TAG" \
  --notes "Dotward $TAG" \
  --draft
echo "        ✓ Release created (draft)"

# ── Step 4: Upload assets one by one with progress ────────────────────────
echo ""
echo "  [4/4] Uploading assets..."
echo ""

RELEASE_JSON=$(gh api repos/Anuvrat14/dotward/releases/tags/$TAG)
UPLOAD_URL=$(echo $RELEASE_JSON | python3 -c "import sys,json; print(json.load(sys.stdin)['upload_url'].replace('{?name,label}',''))")

upload_file() {
  local filepath="$1"
  local filename=$(basename "$filepath")
  local mimetype="$2"
  echo -n "        Uploading $filename "
  curl -# -X POST "${UPLOAD_URL}?name=${filename}" \
    -H "Authorization: Bearer $(gh auth token)" \
    -H "Content-Type: $mimetype" \
    --data-binary "@$filepath" \
    -o /dev/null 2>&1 | grep -oE '[0-9]+%' | tail -1 || true
  echo "✓"
}

upload_file "dist/Dotward-${VERSION}-arm64.dmg"      "application/octet-stream"
upload_file "dist/Dotward-${VERSION}-arm64-mac.zip"  "application/zip"
upload_file "dist/Dotward-${VERSION}.dmg"            "application/octet-stream"
upload_file "dist/Dotward-${VERSION}-mac.zip"        "application/zip"
upload_file "dist/latest-mac.yml"                    "text/yaml"

# ── Publish ────────────────────────────────────────────────────────────────
echo ""
echo "  Publishing release..."
gh release edit $TAG --draft=false
echo ""
echo "  ✓ Dotward $TAG released!"
echo "  https://github.com/Anuvrat14/dotward/releases/tag/$TAG"
echo ""
