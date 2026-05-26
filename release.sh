#!/bin/bash
set -e

# ── Version bump ───────────────────────────────────────────────────────────
# Usage: ./release.sh          → auto patch bump (1.4.1 → 1.4.2)
#        ./release.sh minor    → minor bump (1.4.x → 1.5.0)
#        ./release.sh major    → major bump (1.x.x → 2.0.0)
#        ./release.sh nobump   → use current version as-is

BUMP=${1:-patch}

if [ "$BUMP" != "nobump" ]; then
  npm version $BUMP --no-git-tag-version > /dev/null
fi

VERSION=$(node -p "require('./package.json').version")
TAG="v$VERSION"

# Commit the version bump
git add package.json
git commit -m "chore: bump version to $VERSION" --no-verify 2>/dev/null || true
git push 2>/dev/null || true

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
npx electron-builder --mac --arm64 --publish never 2>&1 | grep -E "•|building|error" | sed 's/^/        /'
echo "        ✓ DMG built"

# ── Step 3: GitHub Release ─────────────────────────────────────────────────
echo ""
echo "  [3/4] Creating GitHub release $TAG..."
gh release delete $TAG --yes 2>/dev/null || true

RELEASE_JSON=$(gh api repos/Anuvrat14/dotward/releases \
  --method POST \
  --field tag_name="$TAG" \
  --field name="Dotward $TAG" \
  --field body="Dotward $TAG" \
  --field draft=true)

RELEASE_ID=$(echo $RELEASE_JSON | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
UPLOAD_URL=$(echo $RELEASE_JSON | python3 -c "import sys,json; print(json.load(sys.stdin)['upload_url'].replace('{?name,label}',''))")
echo "        ✓ Release created (draft, id=$RELEASE_ID)"

# ── Step 4: Upload assets one by one with progress ────────────────────────
echo ""
echo "  [4/4] Uploading assets..."
echo ""

upload_file() {
  local filepath="$1"
  local filename=$(basename "$filepath")
  echo -n "        Uploading $filename ... "
  if gh release upload "$TAG" "$filepath" --clobber 2>&1; then
    echo "✓"
  else
    echo "✗ FAILED"
    exit 1
  fi
}

upload_file "dist/Dotward-${VERSION}-arm64.dmg"
upload_file "dist/Dotward-${VERSION}-arm64-mac.zip"
upload_file "dist/latest-mac.yml"

# ── Publish ────────────────────────────────────────────────────────────────
echo ""
echo "  Publishing release..."
gh api repos/Anuvrat14/dotward/releases/$RELEASE_ID \
  --method PATCH \
  --field draft=false > /dev/null
echo ""
echo "  ✓ Dotward $TAG released!"
echo "  https://github.com/Anuvrat14/dotward/releases/tag/$TAG"
echo ""
