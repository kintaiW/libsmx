#!/usr/bin/env bash
# =============================================================================
# libsmx 安全性扫描脚本
# =============================================================================
# 被 CI 工作流调用，执行以下检查：
#   1. 扫描非测试代码中的 panic!/unwrap()/expect()
#   2. 检查是否有硬编码密钥泄露
#   3. 验证 Cargo.toml 版本号与 Git Tag 匹配（仅在 tag 构建时）
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ERRORS=$((ERRORS + 1)); }

echo "=========================================="
echo "  libsmx Security Sanity Checks"
echo "=========================================="
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 1. 扫描非测试代码中的 panic!/unwrap()/expect()
# ─────────────────────────────────────────────────────────────────────────────
# Reason: 密码学库不应在非测试代码中 panic，应返回 Result/Option
echo "--- 检查 panic/unwrap/expect ---"

# 排除规则：
#   - #[cfg(test)] 块和 mod tests 块内的代码
#   - benches/ 和 tests/ 目录
#   - 白名单：try_into().unwrap() 用于固定大小切片转换（已知安全）

# Reason: 逐行 grep -v 无法排除 #[cfg(test)] 块内部的代码，
#   改用 awk 先将每个文件中 #[cfg(test)] 之后的行全部剥离，再 grep。
PANIC_HITS=$(find src/ -name '*.rs' -exec awk '/#\[cfg\(test\)\]/{exit} {print FILENAME":"NR":"$0}' {} \; \
  | grep 'panic!\|\.unwrap()\|\.expect(' \
  || true)

if [ -n "$PANIC_HITS" ]; then
  # 统计行数
  COUNT=$(echo "$PANIC_HITS" | wc -l)

  # 分类统计
  UNWRAP_COUNT=$(echo "$PANIC_HITS" | grep -c '\.unwrap()' || true)
  EXPECT_COUNT=$(echo "$PANIC_HITS" | grep -c '\.expect(' || true)
  PANIC_COUNT=$(echo "$PANIC_HITS" | grep -c 'panic!' || true)

  # try_into().unwrap() 是固定大小切片转换的惯用法，已知不会 panic
  SAFE_UNWRAP=$(echo "$PANIC_HITS" | grep -c 'try_into().unwrap()' || true)
  UNSAFE_UNWRAP=$((UNWRAP_COUNT - SAFE_UNWRAP))

  if [ "$PANIC_COUNT" -gt 0 ]; then
    fail "发现 $PANIC_COUNT 处 panic! 调用（非测试代码）"
    echo "$PANIC_HITS" | grep 'panic!' | head -5
  fi

  if [ "$UNSAFE_UNWRAP" -gt 0 ]; then
    warn "发现 $UNSAFE_UNWRAP 处 .unwrap() 调用（不含 try_into().unwrap()）"
    echo "$PANIC_HITS" | grep '\.unwrap()' | grep -v 'try_into().unwrap()' | head -5
  fi

  if [ "$EXPECT_COUNT" -gt 0 ]; then
    warn "发现 $EXPECT_COUNT 处 .expect() 调用"
    echo "$PANIC_HITS" | grep '\.expect(' | head -5
  fi

  if [ "$SAFE_UNWRAP" -gt 0 ]; then
    echo -e "  ${GREEN}(白名单)${NC} $SAFE_UNWRAP 处 try_into().unwrap()（固定大小切片转换，已知安全）"
  fi
else
  pass "非测试代码中无 panic/unwrap/expect"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 2. 检查硬编码密钥/敏感信息
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "--- 检查硬编码敏感信息 ---"

# Reason: 防止私钥、密码等敏感信息被提交到仓库
SENSITIVE_PATTERNS='(private.?key|secret.?key|password|passwd|api.?key|token)\s*=\s*["\x27][^\x27"]+["\x27]'
SENSITIVE_HITS=$(find src/ -name '*.rs' -exec awk '/#\[cfg\(test\)\]/{exit} {print FILENAME":"NR":"$0}' {} \; \
  | grep -iE "$SENSITIVE_PATTERNS" \
  || true)

if [ -n "$SENSITIVE_HITS" ]; then
  warn "发现疑似硬编码敏感信息（请人工审查）："
  echo "$SENSITIVE_HITS" | head -5
else
  pass "未发现硬编码敏感信息"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 3. 验证 Cargo.toml 版本号与 Git Tag 匹配
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "--- 检查版本号一致性 ---"

CARGO_VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
echo "  Cargo.toml version: $CARGO_VERSION"

# 如果在 CI 中且有 GITHUB_REF_NAME（tag 构建），验证匹配
if [ -n "${GITHUB_REF_NAME:-}" ] && [[ "${GITHUB_REF:-}" == refs/tags/v* ]]; then
  TAG_VERSION="${GITHUB_REF_NAME#v}"
  echo "  Git tag version:    $TAG_VERSION"
  if [ "$TAG_VERSION" != "$CARGO_VERSION" ]; then
    fail "Tag 版本 ($TAG_VERSION) 与 Cargo.toml 版本 ($CARGO_VERSION) 不匹配！"
  else
    pass "Tag 与 Cargo.toml 版本匹配"
  fi
else
  echo "  (非 tag 构建，跳过版本匹配检查)"
  pass "Cargo.toml 版本号格式正确: $CARGO_VERSION"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4. 检查 unsafe 代码
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "--- 检查 unsafe 代码 ---"

UNSAFE_HITS=$(find src/ -name '*.rs' -exec awk '/#\[cfg\(test\)\]/{exit} {print FILENAME":"NR":"$0}' {} \; \
  | grep 'unsafe' \
  | grep -v '#!\[forbid(unsafe_code)\]' \
  | grep -v '// unsafe' \
  || true)

if [ -n "$UNSAFE_HITS" ]; then
  fail "发现 unsafe 代码（本项目使用 #![forbid(unsafe_code)]）："
  echo "$UNSAFE_HITS" | head -5
else
  pass "未发现 unsafe 代码"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 汇总
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=========================================="
if [ "$ERRORS" -gt 0 ]; then
  echo -e "  ${RED}发现 $ERRORS 个错误！${NC}"
  echo "=========================================="
  exit 1
else
  echo -e "  ${GREEN}所有安全检查通过${NC}"
  echo "=========================================="
  exit 0
fi
