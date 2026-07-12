"""Загрузка обученного классификатора маршрутизации SetFit для сервиса разбора
первопричин kube-sentinel. Модель обучает отдельный тренер (сервис rca-trainer),
складывает её версионированным архивом в объектное хранилище S3 и обновляет
указатель latest. Здесь модель при необходимости синхронизируется из S3 в локальный
каталог и загружается для инференса.

Загрузка выполнена с мягкой деградацией: без установленного пакета SetFit, без
настроенного S3 или без готовой модели функция load возвращает None, и каскад
маршрутизации падает на детерминированный ключевой фолбэк с эскалацией к большой
модели-учителю.

Классификатор многометочный по канону веток BRANCHES. Метод predict_with_confidence
возвращает выбранные ветки (вероятность не ниже порога отбора) и уверенность,
рассчитанную по ВЫБРАННЫМ веткам, а не по максимуму всех классов. Такой расчёт
согласован с логикой каскада: эскалация к большой модели должна срабатывать тогда,
когда сама выбранная разметка ненадёжна, а не тогда, когда какой-то невыбранный
класс случайно оказался близко к границе.

Конфигурация берётся из переменных окружения с единым префиксом SENTINEL_ согласно
контракту продукта (docs/CONVENTIONS.md).
"""
from __future__ import annotations

import os
import tarfile

from router import BRANCHES

# Каталог локальной распаковки модели и порог отбора ветки.
MODEL_DIR = os.getenv("SENTINEL_SETFIT_DIR", "/tmp/setfit-router")
SELECT_THRESHOLD = float(os.getenv("SENTINEL_SETFIT_SELECT_THRESHOLD", "0.5"))

# Объектное хранилище. Ключ модели собирается из префикса и указателя latest, который
# ведёт тренер. Держать здесь конкретную версию не требуется: сервис всегда тянет ту
# версию, на которую указывает latest, а сам файл latest.json обновляется атомарно
# тренером только после прохождения валидационного гейта.
S3_ENDPOINT = os.getenv("SENTINEL_S3_ENDPOINT", "")
S3_REGION = os.getenv("SENTINEL_S3_REGION", "ru-1")
S3_BUCKET = os.getenv("SENTINEL_S3_BUCKET", "")
MODEL_KEY_PREFIX = os.getenv("SENTINEL_MODEL_KEY_PREFIX", "rca/setfit-router").strip("/")


class _Classifier:
    def __init__(self, model):
        self._m = model

    def predict(self, query: str):
        """Возвращает только выбранные ветки (интерфейс router.route)."""
        labels, _ = self.predict_with_confidence(query)
        return labels

    def predict_with_confidence(self, query: str):
        """Возвращает (выбранные ветки, уверенность). Ветка выбирается, если её
        вероятность не ниже порога отбора. Уверенность рассчитывается по выбранным
        веткам как минимальная вероятность среди них: маршрут считается надёжным лишь
        тогда, когда надёжна КАЖДАЯ выбранная ветка. Если не выбрано ничего, уверенность
        равна нулю, что заставляет каскад эскалировать к большой модели."""
        row = self._m.predict_proba([query])[0]
        vals = [float(p) for p in row]
        selected = [
            (BRANCHES[i], p)
            for i, p in enumerate(vals)
            if i < len(BRANCHES) and p >= SELECT_THRESHOLD
        ]
        labels = [b for b, _ in selected]
        conf = min(p for _, p in selected) if selected else 0.0
        return labels, conf


def _safe_extract(tar: tarfile.TarFile, dest: str) -> None:
    """Безопасно распаковывает архив в каталог dest, не позволяя выйти за его пределы.

    Наивный вызов extractall без фильтра членов уязвим к атаке tar-slip: подменённый в
    S3 архив, содержащий члены с абсолютными путями или последовательностями `..`,
    либо символические и жёсткие ссылки, способен записать файлы по произвольным путям
    файловой системы. Начиная с Python 3.12 доступен встроенный фильтр data, который
    отклоняет такие члены. На более ранних версиях выполняется ручная проверка того,
    что нормализованный путь каждого члена лежит строго внутри dest, а ссылки
    отклоняются полностью."""
    dest_real = os.path.realpath(dest)

    # Предпочтительный путь: встроенный фильтр data (Python 3.12 и новее). Он отклоняет
    # абсолютные пути, выход за пределы каталога и опасные ссылки.
    try:
        tar.extractall(dest, filter="data")
        return
    except TypeError:
        # Параметр filter не поддерживается на этой версии Python: ручная проверка ниже.
        pass

    for member in tar.getmembers():
        # Ссылки любого рода отклоняются: цель ссылки может указывать наружу каталога.
        if member.islnk() or member.issym():
            raise ValueError(f"архив содержит ссылку, отклонён: {member.name!r}")
        target = os.path.realpath(os.path.join(dest_real, member.name))
        if target != dest_real and not target.startswith(dest_real + os.sep):
            raise ValueError(f"член архива выходит за пределы каталога: {member.name!r}")
    tar.extractall(dest)


def _resolve_latest_key(s3) -> str:
    """Определяет ключ архива актуальной модели по указателю latest.

    Тренер после успешного прохождения валидационного гейта пишет объект
    `<prefix>/latest.json` с полем key, указывающим на версионированный архив. Если
    указатель недоступен или не читается, используется исторический ключ
    `<prefix>.tar.gz` как совместимый фолбэк, чтобы сервис поднялся даже до первой
    выгрузки нового формата."""
    fallback = f"{MODEL_KEY_PREFIX}.tar.gz"
    try:
        import json

        obj = s3.get_object(Bucket=S3_BUCKET, Key=f"{MODEL_KEY_PREFIX}/latest.json")
        pointer = json.loads(obj["Body"].read().decode("utf-8"))
        key = str(pointer.get("key") or "").strip()
        return key or fallback
    except Exception:
        return fallback


def sync_from_s3(dest: str = MODEL_DIR) -> bool:
    """Скачивает и безопасно распаковывает архив актуальной модели из S3 в каталог
    dest. Возвращает True при успехе. Best-effort: при отсутствии S3, драйвера или
    ошибке возвращает False."""
    if not (S3_ENDPOINT and S3_BUCKET):
        return False
    tmp = None
    try:
        import tempfile

        import boto3

        s3 = boto3.client(
            "s3", endpoint_url=S3_ENDPOINT, region_name=S3_REGION,
            aws_access_key_id=os.getenv("SENTINEL_S3_ACCESS_KEY"),
            aws_secret_access_key=os.getenv("SENTINEL_S3_SECRET_KEY"))
        key = _resolve_latest_key(s3)
        tmp = tempfile.mkdtemp()
        tar = os.path.join(tmp, "model.tar.gz")
        s3.download_file(S3_BUCKET, key, tar)
        # Архив содержит каталог setfit-router; распаковываем в родителя dest.
        parent = os.path.dirname(dest.rstrip("/")) or "."
        os.makedirs(parent, exist_ok=True)
        with tarfile.open(tar) as t:
            _safe_extract(t, parent)
        return os.path.isdir(dest) and bool(os.listdir(dest))
    except Exception:
        return False
    finally:
        if tmp:
            import shutil

            shutil.rmtree(tmp, ignore_errors=True)


def load(model_dir: str = MODEL_DIR):
    """Синхронизирует модель из S3 при необходимости и загружает её. Возвращает None,
    если SetFit не установлен, S3 не настроен или модели нет."""
    try:
        if not (os.path.isdir(model_dir) and os.listdir(model_dir)):
            sync_from_s3(model_dir)
        if not (os.path.isdir(model_dir) and os.listdir(model_dir)):
            return None
        from setfit import SetFitModel

        return _Classifier(SetFitModel.from_pretrained(model_dir))
    except Exception:
        return None
