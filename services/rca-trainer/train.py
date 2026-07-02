"""Тренер классификатора маршрутизации SetFit (ADR-0032, Часть B; книга Биркина,
глава 10). Периодически (CronJob на GPU-узле) читает накопленные размеченные
примеры из Postgres, и если новых достаточно, дообучает многометочный SetFit на
базе rubert-tiny2, выгружает модель архивом в S3 и помечает примеры обученными.
Большая модель (Gemma 4) поставляет разметку через каскад эскалации, а этот тренер
превращает её в дешёвый локальный классификатор, который со временем всё точнее.

Обучение по умолчанию на центральном процессоре (RCA_TRAIN_DEVICE=cpu), чтобы не
конкурировать с vLLM за видеопамять на GPU-узле. Любой сбой логируется и не роняет
задание жёстко: следующий запуск повторит.

ENV: POSTGRES_DSN, S3_ENDPOINT, S3_REGION, S3_ACCESS_KEY, S3_SECRET_KEY,
     RCA_MODEL_BUCKET (default S3_BUCKET_RESULTS), RCA_MODEL_KEY, RCA_SETFIT_BASE,
     RCA_TRAIN_MIN_NEW (порог новых примеров), RCA_TRAIN_DEVICE.
"""
from __future__ import annotations

import json
import os
import tarfile
import tempfile
import time

BRANCHES = ("logs", "alerts", "network", "anomalies", "dependencies", "releases")

DSN = os.getenv("POSTGRES_DSN", "")
MIN_NEW = int(os.getenv("RCA_TRAIN_MIN_NEW", "8"))
BASE = os.getenv("RCA_SETFIT_BASE", "cointegrated/rubert-tiny2")
DEVICE = os.getenv("RCA_TRAIN_DEVICE", "cpu")
S3_ENDPOINT = os.getenv("S3_ENDPOINT", "")
S3_REGION = os.getenv("S3_REGION", "ru-1")
S3_BUCKET = os.getenv("RCA_MODEL_BUCKET", os.getenv("S3_BUCKET_RESULTS", ""))
S3_KEY = os.getenv("RCA_MODEL_KEY", "rca/setfit-router.tar.gz")


def _log(msg: str, **fields) -> None:
    obj = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "level": "info",
           "service": "rca-trainer", "msg": msg}
    obj.update(fields)
    print(json.dumps(obj, ensure_ascii=False), flush=True)


def _multihot(labels) -> list:
    s = set(labels or [])
    return [1 if b in s else 0 for b in BRANCHES]


def fetch_examples():
    import psycopg2

    conn = psycopg2.connect(DSN)
    try:
        with conn, conn.cursor() as cur:
            cur.execute("SELECT id, query, labels, (trained_at IS NULL) FROM rca_route_examples")
            rows = cur.fetchall()
    finally:
        conn.close()
    return rows  # (id, query, labels[], is_new)


def mark_trained(ids) -> None:
    import psycopg2

    conn = psycopg2.connect(DSN)
    try:
        with conn, conn.cursor() as cur:
            # id это uuid, а массив из Python приходит как text[]: явно приводим параметр к uuid[],
            # иначе Postgres ругается «operator does not exist: uuid = text».
            cur.execute("UPDATE rca_route_examples SET trained_at = now() WHERE id = ANY(%s::uuid[])",
                        ([str(i) for i in ids],))
    finally:
        conn.close()


def train_and_upload(rows) -> None:
    from datasets import Dataset
    from setfit import SetFitModel, Trainer, TrainingArguments

    texts = [r[1] for r in rows]
    labels = [_multihot(r[2]) for r in rows]
    model = SetFitModel.from_pretrained(BASE, multi_target_strategy="one-vs-rest", device=DEVICE)
    ds = Dataset.from_dict({"text": texts, "label": labels})
    # Чекпойнты пишем в /tmp: рабочий каталог /app принадлежит root, а контейнер бежит под
    # непривилегированным пользователем, поэтому запись в каталог по умолчанию «checkpoints»
    # в cwd падает с Permission denied.
    ckpt_dir = os.path.join(tempfile.gettempdir(), "setfit-checkpoints")
    trainer = Trainer(model=model, train_dataset=ds,
                      args=TrainingArguments(batch_size=16, num_epochs=1, output_dir=ckpt_dir))
    trainer.train()

    workdir = tempfile.mkdtemp()
    model_dir = os.path.join(workdir, "setfit-router")
    model.save_pretrained(model_dir)
    tar_path = os.path.join(workdir, "setfit-router.tar.gz")
    with tarfile.open(tar_path, "w:gz") as t:
        t.add(model_dir, arcname="setfit-router")

    import boto3

    s3 = boto3.client(
        "s3", endpoint_url=S3_ENDPOINT, region_name=S3_REGION,
        aws_access_key_id=os.getenv("S3_ACCESS_KEY"), aws_secret_access_key=os.getenv("S3_SECRET_KEY"))
    s3.upload_file(tar_path, S3_BUCKET, S3_KEY)
    _log("model uploaded", bucket=S3_BUCKET, key=S3_KEY)


def _notify_reload() -> None:
    """Просит rca-сервис перечитать модель после выгрузки (best-effort)."""
    url = os.getenv("RCA_RELOAD_URL", "http://rca:9107/reload-model")
    try:
        import urllib.request

        urllib.request.urlopen(urllib.request.Request(url, method="POST"), timeout=10)
    except Exception:
        pass


def main() -> None:
    if not DSN or not S3_BUCKET:
        _log("skip: no POSTGRES_DSN or bucket")
        return
    try:
        rows = fetch_examples()
    except Exception as e:
        _log("db read failed", err=str(e))
        return
    new = [r for r in rows if r[3]]
    distinct_branches = {b for r in rows for b in (r[2] or [])}
    if len(new) < MIN_NEW:
        _log("not enough new examples", new=len(new), need=MIN_NEW)
        return
    if len(distinct_branches) < 2:
        _log("need at least two distinct branches", branches=len(distinct_branches))
        return
    _log("training", examples=len(rows), new=len(new), device=DEVICE)
    try:
        train_and_upload(rows)
        mark_trained([r[0] for r in rows])
        _notify_reload()
        _log("done", examples=len(rows))
    except Exception as e:
        # Провал обучения не должен маскироваться под успех: выходим ненулевым кодом, чтобы Job
        # отразил ошибку, а примеры остались непомеченными (mark_trained не вызывался) и попали в
        # следующую попытку.
        _log("training failed", err=str(e))
        import sys
        sys.exit(1)


if __name__ == "__main__":
    main()
