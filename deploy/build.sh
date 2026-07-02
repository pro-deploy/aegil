#!/usr/bin/env bash
# Сборка образов kube-sentinel и публикация в реестр. Все образы несут одну версию (VERSION) и
# тянутся кластером из реестра. Запускать там, где есть docker и доступ к реестру. Тяжёлые образы
# (rca, rca-trainer) собираются на любом узле с достаточными ресурсами.
#
# Переменные:
#   VERSION   версия образов (по умолчанию 0.1.0)
#   REGISTRY  адрес реестра (обязательно задать, например registry.example.com:5000)
#   GROUP     что собирать: all | core (по умолчанию all)
set -euo pipefail

VERSION="${VERSION:-0.1.0}"
REGISTRY="${REGISTRY:?задайте REGISTRY, например registry.example.com:5000}"
GROUP="${GROUP:-all}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

build_push() { # имя контекст [dockerfile]
  local name="$1" ctx="$2" df="${3:-}"
  local img="${REGISTRY}/kube-sentinel/${name}:${VERSION}"
  echo ">> сборка ${img}"
  if [ -n "$df" ]; then docker build -t "$img" -f "$df" "$ctx"; else docker build -t "$img" "$ctx"; fi
  echo ">> публикация"
  docker push "$img"
}

build_push node-agent  "$ROOT/services/node-agent"
build_push agent-panel "$ROOT/services/agent-panel"
build_push rca         "$ROOT/services/rca"
build_push rca-trainer "$ROOT/services/rca-trainer"

echo "Готово: образы kube-sentinel/*:${VERSION} опубликованы в ${REGISTRY}."
