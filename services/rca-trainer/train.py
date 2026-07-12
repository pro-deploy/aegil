"""Тренер классификатора маршрутизации SetFit для сервиса разбора первопричин
aegil. Периодически (по расписанию CronJob) читает накопленные размеченные
примеры из Postgres, и если новых достаточно, дообучает многометочный классификатор
SetFit на базовой модели-энкодере, выгружает обученную модель ВЕРСИОНИРОВАННЫМ архивом
в объектное хранилище S3, обновляет указатель latest и помечает использованные
примеры обученными. Большая модель-учитель поставляет разметку через каскад
эскалации, а этот тренер превращает её в дешёвый локальный классификатор, который со
временем становится точнее.

Ключевые свойства выкладки, введённые согласно контракту версионирования продукта
(docs/CONVENTIONS.md):

Во-первых, версионирование артефакта. Каждая обученная модель кладётся под УНИКАЛЬНЫМ
версионированным ключом, а не перезаписывает единственный ключ на месте. Версия
задаётся снаружи через переменную окружения AEGIL_MODEL_VERSION (например
семантическая версия продукта или таймстамп сборки), потому что в детерминированных
прогонах системное время недоступно. При отсутствии внешней версии тренер отказывается
выгружать модель, чтобы не создать неотличимый по номеру артефакт. Указатель
`<prefix>/latest.json` обновляется атомарно и только после прохождения гейта, поэтому
по нему всегда ясно, какая именно версия сейчас обслуживает продакшн, и возможен откат
на предыдущий версионированный ключ.

Во-вторых, валидационный гейт. Накопленные примеры делятся на обучающую и
валидационную выборки, после обучения считается метрика качества на валидации, и новая
модель продвигается в продакшн (обновляет указатель latest) ТОЛЬКО при превышении
порога. Если метрика ниже порога, версионированный архив всё равно сохраняется для
разбора, но указатель latest не трогается: прежняя рабочая модель остаётся в проде, а
тренер сигналит о деградации ненулевым кодом выхода. Это исключает тихую подмену
хорошей модели деградировавшей.

В-третьих, ограничение роста обучающей таблицы. Обучение идёт не на всей истории
целиком, а на ограниченном по объёму окне свежих примеров, отсортированных по времени
создания, что не даёт стоимости обучения расти безгранично и не переобучает модель на
дубликатах давней истории.

Конфигурация вынесена под единый префикс AEGIL_. Обучение по умолчанию на
центральном процессоре, чтобы не конкурировать за видеопамять. Любой сбой
журналируется и не роняет задание тихо: неуспех отражается ненулевым кодом выхода,
а использованные примеры остаются непомеченными и попадают в следующую попытку.
"""
from __future__ import annotations

import json
import os
import tarfile
import tempfile
import time
from urllib.parse import urlsplit

BRANCHES = ("logs", "alerts", "network", "anomalies", "dependencies", "releases")

DSN = os.getenv("AEGIL_POSTGRES_DSN", "")
MIN_NEW = int(os.getenv("AEGIL_TRAIN_MIN_NEW", "8"))
# Верхняя граница обучающего окна: даже при большой истории обучаемся на ограниченном
# числе самых свежих примеров, чтобы стоимость обучения не росла безгранично.
TRAIN_WINDOW = int(os.getenv("AEGIL_TRAIN_WINDOW", "2000"))
# Доля валидационной выборки и порог метрики для продвижения в прод.
VAL_FRACTION = float(os.getenv("AEGIL_TRAIN_VAL_FRACTION", "0.2"))
METRIC_THRESHOLD = float(os.getenv("AEGIL_TRAIN_METRIC_THRESHOLD", "0.6"))
BASE = os.getenv("AEGIL_SETFIT_BASE", "cointegrated/rubert-tiny2")
DEVICE = os.getenv("AEGIL_TRAIN_DEVICE", "cpu")
SEED = int(os.getenv("AEGIL_TRAIN_SEED", "13"))

S3_ENDPOINT = os.getenv("AEGIL_S3_ENDPOINT", "")
S3_REGION = os.getenv("AEGIL_S3_REGION", "ru-1")
S3_BUCKET = os.getenv("AEGIL_S3_BUCKET", "")
MODEL_KEY_PREFIX = os.getenv("AEGIL_MODEL_KEY_PREFIX", "rca/setfit-router").strip("/")
# Внешняя версия артефакта (семантическая версия или таймстамп сборки). Обязательна:
# без неё тренер не выгружает модель, чтобы не создать неотличимый по номеру артефакт.
MODEL_VERSION = os.getenv("AEGIL_MODEL_VERSION", "").strip()


def _log(msg: str, level: str = "info", **fields) -> None:
    obj = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "level": level,
           "service": "rca-trainer", "msg": msg}
    obj.update(fields)
    print(json.dumps(obj, ensure_ascii=False), flush=True)


def _multihot(labels) -> list:
    s = set(labels or [])
    return [1 if b in s else 0 for b in BRANCHES]


def fetch_examples():
    """Читает ограниченное окно самых свежих примеров. Возвращает строки вида
    (id, query, labels[], is_new). Ограничение окна не даёт обучаться на всей истории
    с накопленными давними дубликатами."""
    import psycopg2

    conn = psycopg2.connect(DSN)
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, query, labels, (trained_at IS NULL) "
                "FROM rca_route_examples ORDER BY created_at DESC NULLS LAST LIMIT %s",
                (TRAIN_WINDOW,),
            )
            rows = cur.fetchall()
    finally:
        conn.close()
    return rows


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


def split_train_val(rows, val_fraction: float = VAL_FRACTION, seed: int = SEED):
    """Детерминированно делит строки на обучающую и валидационную выборки. Деление
    зависит только от переданного зерна, чтобы прогон был воспроизводим. Валидационная
    выборка не пуста при достаточном числе строк, но и не забирает всё."""
    import random

    ordered = list(rows)
    rnd = random.Random(seed)
    rnd.shuffle(ordered)
    n_val = int(len(ordered) * val_fraction)
    n_val = max(1, min(n_val, len(ordered) - 1)) if len(ordered) >= 2 else 0
    val = ordered[:n_val]
    train = ordered[n_val:]
    return train, val


def evaluate(model, val_rows) -> float:
    """Считает метрику качества на валидации: микро-усреднённую F1 по многометочному
    предсказанию. Возвращает значение в диапазоне от нуля до единицы. При пустой
    валидации возвращает ноль, что не даёт продвинуть модель без проверки."""
    if not val_rows:
        return 0.0
    texts = [r[1] for r in val_rows]
    gold = [_multihot(r[2]) for r in val_rows]
    proba = model.predict_proba(texts)
    tp = fp = fn = 0
    for row_proba, gold_row in zip(proba, gold):
        pred = [1 if float(p) >= 0.5 else 0 for p in row_proba]
        for pr, gd in zip(pred, gold_row):
            if pr == 1 and gd == 1:
                tp += 1
            elif pr == 1 and gd == 0:
                fp += 1
            elif pr == 0 and gd == 1:
                fn += 1
    denom = 2 * tp + fp + fn
    return (2 * tp / denom) if denom else 0.0


def _s3_client():
    import boto3

    return boto3.client(
        "s3", endpoint_url=S3_ENDPOINT, region_name=S3_REGION,
        aws_access_key_id=os.getenv("AEGIL_S3_ACCESS_KEY"),
        aws_secret_access_key=os.getenv("AEGIL_S3_SECRET_KEY"))


def _versioned_key(version: str) -> str:
    """Собирает уникальный версионированный ключ архива. Версия санируется до
    безопасного набора символов, чтобы не сконструировать посторонний путь в бакете."""
    import re

    # Заменяем всё, кроме букв, цифр, точки, подчёркивания и дефиса, на дефис; затем
    # схлопываем последовательности точек (чтобы не осталось `..`) и повторные дефисы.
    safe = re.sub(r"[^A-Za-z0-9._-]", "-", version)
    safe = re.sub(r"\.{2,}", ".", safe)
    safe = re.sub(r"-{2,}", "-", safe).strip("-.") or "unknown"
    return f"{MODEL_KEY_PREFIX}/versions/{safe}.tar.gz"


def train_model(rows):
    """Обучает многометочный SetFit на переданных строках и возвращает обученную
    модель. Строки уже ограничены окном и относятся к обучающей выборке."""
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
    return model


def upload_version(model, version: str) -> str:
    """Пакует и выгружает модель под версионированным ключом. Возвращает этот ключ.
    Указатель latest здесь НЕ трогается: его обновляет promote_latest только после
    прохождения валидационного гейта."""
    workdir = tempfile.mkdtemp()
    model_dir = os.path.join(workdir, "setfit-router")
    model.save_pretrained(model_dir)
    tar_path = os.path.join(workdir, "setfit-router.tar.gz")
    with tarfile.open(tar_path, "w:gz") as t:
        t.add(model_dir, arcname="setfit-router")

    key = _versioned_key(version)
    s3 = _s3_client()
    s3.upload_file(tar_path, S3_BUCKET, key)
    _log("version uploaded", bucket=S3_BUCKET, key=key, version=version)
    return key


def promote_latest(key: str, version: str, metric: float) -> None:
    """Атомарно переводит указатель latest на переданный версионированный ключ.
    Вызывается только при прохождении валидационного гейта, поэтому по latest всегда
    ясно, какая проверенная версия обслуживает продакшн."""
    pointer = {"key": key, "version": version, "metric": round(metric, 4),
               "promoted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    s3 = _s3_client()
    s3.put_object(Bucket=S3_BUCKET, Key=f"{MODEL_KEY_PREFIX}/latest.json",
                  Body=json.dumps(pointer, ensure_ascii=False).encode("utf-8"),
                  ContentType="application/json")
    _log("latest promoted", key=key, version=version, metric=metric)


def _reload_url_is_safe(url: str) -> bool:
    """Проверяет, что URL перезагрузки указывает на разрешённый хост внутрикластерного
    сервиса. Закрывает подделку запроса на стороне сервера (SSRF): без проверки хоста
    управляемый извне URL мог бы заставить тренер обратиться к произвольному адресу,
    включая метаданные облака или внутренние сервисы. Разрешённый хост задаётся
    владельцем через AEGIL_RCA_RELOAD_ALLOWED_HOSTS (список хостов через запятую);
    при отсутствии списка допускается только хост по умолчанию `rca`."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return False
    host = (parts.hostname or "").lower()
    if not host:
        return False
    allowed_raw = os.getenv("AEGIL_RCA_RELOAD_ALLOWED_HOSTS", "rca")
    allowed = {h.strip().lower() for h in allowed_raw.split(",") if h.strip()}
    return host in allowed


def _notify_reload() -> None:
    """Просит сервис rca перечитать модель после продвижения latest (best-effort).
    URL валидируется по списку разрешённых хостов, чтобы закрыть SSRF."""
    url = os.getenv("AEGIL_RCA_RELOAD_URL", "http://rca:9107/reload-model")
    if not _reload_url_is_safe(url):
        _log("reload skipped: url host not allowed", level="warning", url=url)
        return
    try:
        import urllib.request

        urllib.request.urlopen(urllib.request.Request(url, method="POST"), timeout=10)
    except Exception:
        pass


def main() -> None:
    # Обучение переносим в записываемый временный каталог: рабочий каталог образа принадлежит root,
    # а контейнер бежит под непривилегированным пользователем, поэтому относительные служебные записи
    # обучающего цикла (например каталог tmp_trainer у внутреннего тренера) в cwd падают с Permission
    # denied. Явный переход в tempdir делает такие записи безопасными независимо от прав рабочего каталога.
    os.chdir(tempfile.gettempdir())
    if not DSN or not S3_BUCKET:
        _log("skip: no AEGIL_POSTGRES_DSN or bucket")
        return
    if not MODEL_VERSION:
        # Без внешней версии выгрузка запрещена: иначе артефакт был бы неотличим по
        # номеру от предыдущего, что ломает откат и понимание, что на проде.
        _log("skip: AEGIL_MODEL_VERSION not set", level="warning")
        return
    try:
        rows = fetch_examples()
    except Exception as e:
        _log("db read failed", level="error", err=str(e))
        import sys
        sys.exit(1)
    new = [r for r in rows if r[3]]
    distinct_branches = {b for r in rows for b in (r[2] or [])}
    if len(new) < MIN_NEW:
        _log("not enough new examples", new=len(new), need=MIN_NEW)
        return
    if len(distinct_branches) < 2:
        _log("need at least two distinct branches", branches=len(distinct_branches))
        return

    train_rows, val_rows = split_train_val(rows)
    _log("training", examples=len(rows), train=len(train_rows), val=len(val_rows),
         new=len(new), device=DEVICE, version=MODEL_VERSION)
    try:
        model = train_model(train_rows)
        metric = evaluate(model, val_rows)
        # Версионированный архив сохраняем всегда: он нужен и для продвижения, и для
        # разбора деградации.
        key = upload_version(model, MODEL_VERSION)
        if metric >= METRIC_THRESHOLD:
            promote_latest(key, MODEL_VERSION, metric)
            mark_trained([r[0] for r in rows])
            _notify_reload()
            _log("done: promoted", examples=len(rows), metric=metric, version=MODEL_VERSION)
        else:
            # Гейт не пройден: прежняя рабочая модель остаётся в проде, latest не
            # трогается. Примеры помечаем обученными, чтобы не переобучаться на них
            # бесконечно, но сигналим ненулевым кодом о деградации.
            mark_trained([r[0] for r in rows])
            _log("gate failed: keeping previous model", level="warning",
                 metric=metric, threshold=METRIC_THRESHOLD, version=MODEL_VERSION)
            import sys
            sys.exit(2)
    except SystemExit:
        raise
    except Exception as e:
        # Провал обучения не должен маскироваться под успех: выходим ненулевым кодом, чтобы Job
        # отразил ошибку, а примеры остались непомеченными (mark_trained не вызывался) и попали в
        # следующую попытку.
        _log("training failed", level="error", err=str(e))
        import sys
        sys.exit(1)


if __name__ == "__main__":
    main()
