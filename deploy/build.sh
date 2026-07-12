#!/usr/bin/env bash
# Сборка образов aegil и публикация в реестр. Все образы продукта несут ОДНУ и ту же
# семантическую версию (VERSION) и тянутся кластером из реестра. На каждый деплой присваивается
# НОВАЯ версия: перезапись уже выпущенного тега на месте запрещена (см. проверку ниже), потому
# что иначе по номеру версии невозможно понять, какой именно код работает на кластере, и ломается
# откат. Версия фиксируется git-тегом vX.Y.Z в соответствии с docs/CONVENTIONS.md.
#
# Запускать там, где есть docker и доступ к реестру.
#
# Переменные:
#   VERSION       семантическая версия образов, обязательна (например 0.1.0). Должна совпадать с
#                 версией чарта и тегами образов в манифестах.
#   REGISTRY      адрес реестра, обязателен (например registry.example.com:5000).
#   GROUP         что собирать: all (по умолчанию, все образы) либо core (только панель и rca,
#                 без тяжёлого тренера и без узлового агента, удобно для быстрой пересборки ядра).
#   PLATFORM      целевая платформа образов (по умолчанию linux/amd64), под архитектуру узлов
#                 целевого кластера. Сборка идёт через buildx, чтобы образ, собранный на машине
#                 с иной архитектурой (например arm64 Apple Silicon), запускался на amd64-узлах.
#   ALLOW_TAG_OVERWRITE  установите в 1, только если осознанно перезаписываете уже выпущенный
#                 тег (обычно этого делать нельзя, см. выше).
set -euo pipefail

VERSION="${VERSION:?задайте VERSION по семантическому версионированию, например 0.1.0}"
REGISTRY="${REGISTRY:?задайте REGISTRY, например registry.example.com:5000}"
GROUP="${GROUP:-all}"
PLATFORM="${PLATFORM:-linux/amd64}"
ALLOW_TAG_OVERWRITE="${ALLOW_TAG_OVERWRITE:-0}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "$GROUP" != "all" && "$GROUP" != "core" ]]; then
  echo "GROUP должен быть all или core, получено: $GROUP" >&2
  exit 2
fi

# Запрет перезаписи выпущенного тега: если образ с такой версией уже есть в реестре, сборка
# останавливается, чтобы не подменить содержимое под тем же номером. Проверка через manifest
# inspect не требует скачивания образа.
assert_tag_free() { # имя
  local img="${REGISTRY}/aegil/${1}:${VERSION}"
  if [[ "$ALLOW_TAG_OVERWRITE" == "1" ]]; then
    return 0
  fi
  if docker manifest inspect "$img" >/dev/null 2>&1; then
    echo "тег уже выпущен в реестре: $img" >&2
    echo "перезапись выпущенного тега запрещена; увеличьте VERSION по семантическому версионированию" >&2
    echo "(для осознанной перезаписи задайте ALLOW_TAG_OVERWRITE=1)" >&2
    exit 3
  fi
}

build_push() { # имя контекст [dockerfile]
  local name="$1" ctx="$2" df="${3:-}"
  local img="${REGISTRY}/aegil/${name}:${VERSION}"
  assert_tag_free "$name"
  echo ">> сборка ${img} (платформа ${PLATFORM})"
  if [ -n "$df" ]; then
    docker buildx build --platform "$PLATFORM" -t "$img" -f "$df" --push "$ctx"
  else
    docker buildx build --platform "$PLATFORM" -t "$img" --push "$ctx"
  fi
}

build_push agent-panel "$ROOT/services/agent-panel"
build_push rca         "$ROOT/services/rca"
if [[ "$GROUP" == "all" ]]; then
  build_push node-agent  "$ROOT/services/node-agent"
  build_push rca-trainer "$ROOT/services/rca-trainer"
fi

# Фиксация версии git-тегом vX.Y.Z: тег привязывает выпущенные образы к конкретному коммиту,
# чтобы по номеру всегда было ясно, какой код собран. Если тег уже существует, он не
# переставляется (перезапись выпущенного тега запрещена и в git).
if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  if git -C "$ROOT" rev-parse "v${VERSION}" >/dev/null 2>&1; then
    echo ">> git-тег v${VERSION} уже существует, не переставляю"
  else
    git -C "$ROOT" tag -a "v${VERSION}" -m "aegil ${VERSION}"
    echo ">> проставлен git-тег v${VERSION} (запушьте его: git push origin v${VERSION})"
  fi
fi

echo "Готово: образы aegil/*:${VERSION} (группа ${GROUP}) опубликованы в ${REGISTRY}."
