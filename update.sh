#!/usr/bin/env bash
# 在项目根目录执行（cd /Users/raylanhu/Downloads/ctfSolver-master\ 2）
set -euo pipefail

REPO_DIR="/Users/raylanhu/Downloads/ctfSolver-master 2"
REMOTE="https://github.com/passer-W/sceneStrike.git"

cd "$REPO_DIR"

# 1. 首次：初始化仓库（已存在则跳过）
if [ ! -d .git ]; then
  git init -b master
fi

# 2. 本地提交者信息（仅本仓库，不污染全局）
git config user.email "raylanhu@users.noreply.github.com"
git config user.name  "raylanhu"

# 3. 暂存全部变更
git add -A

# 4. 提交
git commit -m "update" || true

# 5. （可选）补一次：把 reports_hackerone 作为第二个提交
git add reports_hackerone/ 2>/dev/null || true
if git diff --cached --quiet; then :; else
  git commit -m "Add reports_hackerone: 11k+ HackerOne disclosure reports"
fi

# 6. 绑定远端
git remote remove origin 2>/dev/null || true
git remote add origin "$REMOTE"

# 7. 推送：调大缓冲与超时（首推 137 MB 偏大）
git config http.postBuffer 524288000
GIT_HTTP_LOW_SPEED_TIME=600 \
GIT_HTTP_LOW_SPEED_LIMIT=1000 \
  git push -u origin master