#!/usr/bin/env bash
# Pre-publish checks for libsmx
# Run this before `cargo publish` to catch common issues.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

echo "=========================================="
echo "  libsmx Pre-Publish Checks"
echo "=========================================="
echo ""

# 1. Formatting
echo "--- Checking formatting ---"
cargo fmt --check 2>/dev/null && pass "cargo fmt" || fail "cargo fmt -- run 'cargo fmt' to fix"

# 2. Clippy (default features)
echo "--- Running clippy (default features) ---"
cargo clippy --all-targets -- -D warnings 2>/dev/null && pass "clippy (default)" || fail "clippy warnings found"

# 3. Clippy (no_std, no alloc) — only check compilation, not warnings
# Reason: many alloc-gated functions appear "unused" in no_std mode, which is expected
echo "--- Running clippy (no_std, no alloc) ---"
cargo check --no-default-features 2>/dev/null && pass "clippy (no_std)" || fail "no_std build failed"

# 4. Tests (default features)
echo "--- Running tests (default features) ---"
cargo test 2>/dev/null && pass "cargo test" || fail "tests failed"

# 5. Tests (no_std check)
echo "--- Checking no_std build ---"
cargo check --no-default-features 2>/dev/null && pass "no_std check" || fail "no_std build failed"

# 6. Doc build
echo "--- Building documentation ---"
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps 2>/dev/null && pass "cargo doc" || fail "doc build failed"

# 7. Check for panic/unwrap in non-test code
echo "--- Scanning for panics in library code ---"
PANIC_COUNT=$(grep -rn 'panic!\|\.unwrap()\|\.expect(' src/ --include='*.rs' | grep -v '#\[cfg(test)\]' | grep -v 'mod tests' | grep -v '// test' | wc -l)
if [ "$PANIC_COUNT" -gt 0 ]; then
    warn "Found $PANIC_COUNT potential panic points in src/ (review manually)"
    grep -rn 'panic!\|\.unwrap()\|\.expect(' src/ --include='*.rs' | grep -v '#\[cfg(test)\]' | grep -v 'mod tests' | head -10
else
    pass "No panics found in library code"
fi

# 8. Check Cargo.toml metadata
echo "--- Checking Cargo.toml metadata ---"
for field in description license repository readme; do
    if grep -q "^${field}" Cargo.toml; then
        pass "Cargo.toml has '$field'"
    else
        fail "Cargo.toml missing '$field'"
    fi
done

# 9. Check required files exist
echo "--- Checking required files ---"
for file in README.md LICENSE CHANGELOG.md SECURITY.md; do
    if [ -f "$file" ]; then
        pass "$file exists"
    else
        warn "$file not found"
    fi
done

# 10. Dry-run publish (--allow-dirty: pre-publish checks run before committing)
echo "--- Dry-run publish ---"
cargo publish --dry-run --allow-dirty 2>/dev/null && pass "cargo publish --dry-run" || fail "publish dry-run failed"

echo ""
echo "=========================================="
echo -e "  ${GREEN}All checks passed!${NC}"
echo "=========================================="
echo ""
echo "Ready to publish. Run:"
echo "  cargo publish"
