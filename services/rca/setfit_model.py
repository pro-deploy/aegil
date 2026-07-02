"""Загрузка обученного классификатора маршрутизации SetFit (ADR-0032, Часть B; книга
Биркина, глава 10). Модель обучает отдельный тренер на GPU-узле и кладёт архивом в
S3. Здесь она при необходимости синхронизируется из S3 в локальный каталог и
загружается для инференса, с мягкой деградацией: без установленного SetFit, без
настроенного S3 или без готовой модели возвращается None, и каскад падает на
детерминированный ключевой фолбэк с эскалацией к Gemma 4.

Классификатор многометочный по канону веток BRANCHES; predict_with_confidence
возвращает выбранные ветки (вероятность не ниже 0,5) и уверенность (максимум
вероятности), как ожидает каскад.
"""
from __future__ import annotations

import os
import tarfile
import tempfile

from router import BRANCHES

MODEL_DIR = os.getenv("RCA_SETFIT_DIR", "/tmp/setfit-router")
S3_ENDPOINT = os.getenv("S3_ENDPOINT", "")
S3_BUCKET = os.getenv("RCA_MODEL_BUCKET", os.getenv("S3_BUCKET_RESULTS", ""))
S3_KEY = os.getenv("RCA_MODEL_KEY", "rca/setfit-router.tar.gz")


class _Classifier:
    def __init__(self, model):
        self._m = model

    def predict_with_confidence(self, query: str):
        row = self._m.predict_proba([query])[0]
        vals = [float(p) for p in row]
        labels = [BRANCHES[i] for i, p in enumerate(vals) if i < len(BRANCHES) and p >= 0.5]
        conf = max(vals) if vals else 0.0
        return labels, conf


def sync_from_s3(dest: str = MODEL_DIR) -> bool:
    """Скачивает и распаковывает архив модели из S3 в каталог dest. Возвращает True
    при успехе. Best-effort: при отсутствии S3, драйвера или ошибке возвращает False."""
    if not (S3_ENDPOINT and S3_BUCKET):
        return False
    try:
        import boto3

        s3 = boto3.client(
            "s3", endpoint_url=S3_ENDPOINT, region_name=os.getenv("S3_REGION", "ru-1"),
            aws_access_key_id=os.getenv("S3_ACCESS_KEY"), aws_secret_access_key=os.getenv("S3_SECRET_KEY"))
        tmp = tempfile.mkdtemp()
        tar = os.path.join(tmp, "model.tar.gz")
        s3.download_file(S3_BUCKET, S3_KEY, tar)
        # Архив содержит каталог setfit-router; распаковываем в родителя dest.
        parent = os.path.dirname(dest.rstrip("/")) or "."
        os.makedirs(parent, exist_ok=True)
        with tarfile.open(tar) as t:
            t.extractall(parent)
        return os.path.isdir(dest) and bool(os.listdir(dest))
    except Exception:
        return False


def load(model_dir: str = MODEL_DIR):
    """Синхронизирует модель из S3 при необходимости и загружает её. None, если SetFit
    не установлен, S3 не настроен или модели нет."""
    try:
        if not (os.path.isdir(model_dir) and os.listdir(model_dir)):
            sync_from_s3(model_dir)
        if not (os.path.isdir(model_dir) and os.listdir(model_dir)):
            return None
        from setfit import SetFitModel

        return _Classifier(SetFitModel.from_pretrained(model_dir))
    except Exception:
        return None
