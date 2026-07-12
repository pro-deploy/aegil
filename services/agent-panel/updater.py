"""Канал самообновления продукта aegil.

Модуль отвечает за то, чтобы продукт умел узнать о выходе своей новой версии по настраиваемому
каналу обновления и, строго с явного подтверждения владельца, перевести собственные деплойменты
на новый тег образа. Обновление образа это высокорисковая мутация инфраструктуры: она приводит к
перекату рабочих нагрузок, поэтому автономно она не выполняется никогда. Единственный способ её
запустить это вызвать ``apply`` с признаком подтверждения ``confirmed=True``, который приходит
только от владельца через интерфейс. Без подтверждения модуль ничего не делает и честно сообщает,
что требуется подтверждение.

Модуль домен-агностичен и не содержит зашитых имён сервисов, реестров, тегов или адресов канала:
адрес канала обновления, целевые деплойменты и пространство имён берутся из конфигурации продукта
с единым префиксом переменных окружения ``AEGIL_``. Обращение за информацией об обновлении идёт
строго по настроенному владельцем адресу канала, без подстановки в него каких бы то ни было
пользовательских данных, что закрывает вектор подделки серверных запросов (Server-Side Request
Forgery). При недоступности канала или при запуске вне кластера модуль мягко деградирует, возвращая
честный признак недоступности вместо падения, единообразно со слоем доступа к API Kubernetes
(модуль ``k8s``). Соглашения продукта описаны в ``docs/CONVENTIONS.md``.

Замечание о самопатче. Панель агента aegil сама является деплойментом в кластере. Если её
имя внесено в список целевых деплойментов ``AEGIL_UPDATE_DEPLOYMENTS``, то обновление образа
приведёт к перекату самой панели: текущий под завершится, планировщик поднимет под с новым тегом
образа. Для Kubernetes это штатное поведение управляемого деплойментом отката, и оно ожидаемо: так
продукт обновляет и себя тоже. Владелец должен понимать, что подтверждение обновления, включающего
собственный деплоймент панели, вызовет кратковременный перезапуск интерфейса.
"""
from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlparse

import httpx

import config

# Путь к файлу VERSION рядом с модулем: запасной источник текущей версии, когда переменная окружения
# AEGIL_VERSION не проставлена манифестом (например, при локальном запуске вне кластера).
_VERSION_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")

# Стандартные пути монтирования сервисного аккаунта пода. Совпадают с путями, которыми пользуется
# слой доступа к API Kubernetes (модуль k8s): единый контур доступа, чтобы поведение внутри и вне
# кластера было одинаковым во всех модулях продукта.
_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# Явные таймауты на сетевые обращения (в секундах). Без таймаута зависший канал обновления или
# недоступный API-сервер заморозили бы обработчик; с таймаутом отказ становится честной ошибкой.
_CHANNEL_TIMEOUT = 10.0
_API_TIMEOUT = 15.0

# Имя ресурса Kubernetes (DNS-1123): единственная допустимая форма имени деплоймента. Проверка до
# подстановки имени в путь API исключает выход за пределы намеченного пути.
_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")

# Разбор семантической версии вида X.Y.Z с необязательным префиксом v. Предвыпускные и метаданные
# сборки (суффиксы после - и +) для сравнения версий продукта не используются и отбрасываются, так
# как продукт выпускается строго тройками мажор.минор.патч (см. раздел версионирования соглашений).
_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")


def _url_block_reason(url: str) -> str:
    """Причина отклонить адрес канала обновления, либо пустая строка, если адрес безопасен. Даже
    настроенный владельцем адрес проверяется в глубину: допускаются только схемы http и https, а
    обращения к петлевым, локальным и служебным адресам метаданных облака (например 169.254.169.254)
    запрещены, чтобы канал обновления нельзя было направить на внутренний ресурс."""
    try:
        u = urlparse(url)
    except ValueError:
        return "некорректный адрес канала обновления"
    if u.scheme not in ("http", "https"):
        return "адрес канала обновления должен использовать http или https"
    host = (u.hostname or "").lower()
    if not host:
        return "адрес канала обновления без хоста"
    # Явно заданный служебный или внутренний адрес отклоняется без сетевого разрешения имени: это
    # закрывает главный вектор (адрес метаданных облака) и не вводит собственного сетевого стока.
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved or ip.is_multicast:
            return f"адрес канала обновления ведёт на служебный или внутренний адрес ({ip})"
    except ValueError:
        if host in ("localhost", "metadata", "metadata.google.internal") or host.endswith(".local"):
            return "адрес канала обновления ведёт на служебный или внутренний хост"
    return ""


def _senv(name: str, default: str = "") -> str:
    """Значение переменной окружения продукта (префикс AEGIL_) с обрезкой пробелов."""
    return os.getenv(name, default).strip()


def current_version() -> str:
    """Возвращает текущую версию продукта.

    Основной источник это переменная окружения ``AEGIL_VERSION``, которую в боевом развёртывании
    проставляет манифест, приводя версию образа и версию, известную коду, в согласие. Если
    переменная не задана, предпринимается попытка прочитать версию из файла ``VERSION``,
    расположенного рядом с модулем. Если недоступны оба источника, возвращается нейтральное
    значение ``0.0.0``, которое при сравнении заведомо старше любой реально выпущенной версии,
    поэтому канал обновления в худшем случае предложит обновиться, а не пропустит обновление."""
    env = _senv("AEGIL_VERSION")
    if env:
        return env
    try:
        with open(_VERSION_FILE, encoding="utf-8") as f:
            file_version = f.read().strip()
        if file_version:
            return file_version
    except OSError:
        pass
    return "0.0.0"


def _parse(v: str) -> tuple[int, int, int] | None:
    """Разбирает строку семантической версии вида ``X.Y.Z`` в кортеж целых чисел
    ``(мажор, минор, патч)``.

    Необязательный префикс ``v`` игнорируется, поэтому ``v1.2.3`` и ``1.2.3`` разбираются
    одинаково. Хвост после третьего числа (предвыпускной суффикс или метаданные сборки) для
    сравнения версий продукта значения не имеет и отбрасывается. Возвращает ``None``, если строка
    не является распознаваемой семантической версией (пустая, содержит мусор, содержит меньше трёх
    числовых компонентов), чтобы вызывающая сторона могла отличить неразбираемую версию от
    настоящей."""
    m = _SEMVER_RE.match(str(v or "").strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _newer(a: str, b: str) -> bool:
    """Возвращает ``True``, если версия ``a`` строго новее версии ``b`` по семантическому
    сравнению, и ``False`` в остальных случаях, включая равенство версий и обратный порядок.

    Сравнение покомпонентное: сначала мажорная часть, затем минорная, затем патч. Неразбираемая
    версия трактуется консервативно: если новизну определить нельзя, потому что хотя бы одна из
    строк не является распознаваемой семантической версией, функция возвращает ``False`` и
    обновление не предлагается, что безопасно для высокорисковой мутации."""
    pa = _parse(a)
    pb = _parse(b)
    if pa is None or pb is None:
        return False
    return pa > pb


def check(*, http=None) -> dict:
    """Проверяет наличие новой версии продукта по настроенному каналу обновления.

    Адрес канала берётся из переменной окружения ``AEGIL_UPDATE_CHANNEL_URL`` и представляет
    собой доверенный владельцем ресурс, отдающий JSON вида
    ``{"version": "X.Y.Z", "image_tag": "...", "notes": "..."}``. Обращение идёт строго по этому
    адресу без подстановки в него каких бы то ни было пользовательских данных, поэтому подделка
    серверных запросов (Server-Side Request Forgery) исключена конструктивно: злоумышленник не
    может заставить продукт обратиться к произвольному адресу.

    Возвращает словарь с полями ``current`` (текущая версия продукта), ``latest`` (версия из
    канала), ``image_tag`` (тег образа для новой версии), ``available`` (булев признак того, что
    версия из канала строго новее текущей) и ``notes`` (примечания к выпуску из канала). При
    отсутствии настроенного адреса, недоступности канала, таймауте, коде ответа класса ошибки или
    нечитаемом либо пустом теле функция мягко деградирует и возвращает
    ``{"available": False, "error": "..."}`` без исключения, единообразно со слоем доступа к API
    Kubernetes.

    Аргумент ``http`` это необязательный инъектируемый клиент, совместимый по интерфейсу с
    ``httpx.Client`` (контекстный менеджер с методом ``get``). Он предназначен для тестов, чтобы не
    выходить в сеть; в боевом режиме создаётся собственный клиент с явным таймаутом."""
    current = current_version()
    url = _senv("AEGIL_UPDATE_CHANNEL_URL")
    if not url:
        return {"current": current, "available": False,
                "error": "канал обновления не настроен (AEGIL_UPDATE_CHANNEL_URL пуст)"}
    block = _url_block_reason(url)
    if block:
        return {"current": current, "available": False, "error": block}
    try:
        if http is not None:
            r = http.get(url)
        else:
            with httpx.Client(timeout=_CHANNEL_TIMEOUT) as cl:
                r = cl.get(url)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return {"current": current, "available": False,
                "error": f"канал обновления недоступен: {e}"}
    if not isinstance(data, dict):
        return {"current": current, "available": False,
                "error": "канал обновления вернул некорректный ответ"}
    latest = str(data.get("version", "")).strip()
    image_tag = str(data.get("image_tag", "")).strip()
    notes = str(data.get("notes", "")).strip()
    if not latest:
        return {"current": current, "available": False,
                "error": "канал обновления не сообщил версию"}
    return {
        "current": current,
        "latest": latest,
        "image_tag": image_tag,
        "available": _newer(latest, current),
        "notes": notes,
    }


def _incluster():
    """Возвращает кортеж ``(base_url, token, ca)`` при запуске в кластере, иначе ``None``.

    Контур доступа тот же, что в слое ``k8s``: адрес API-сервера из переменных окружения,
    подставляемых Kubernetes в каждый под, токен и корневой сертификат из смонтированного
    сервисного аккаунта. Вне кластера (при отсутствии адреса API-сервера или файла токена) функция
    возвращает ``None``, что позволяет вызывающему коду честно отказать вместо падения."""
    host = os.getenv("KUBERNETES_SERVICE_HOST")
    port = os.getenv("KUBERNETES_SERVICE_PORT", "443")
    if not host or not os.path.exists(_TOKEN_PATH):
        return None
    try:
        with open(_TOKEN_PATH, encoding="utf-8") as f:
            token = f.read().strip()
    except OSError:
        return None
    ca = _CA_PATH if os.path.exists(_CA_PATH) else False
    return f"https://{host}:{port}", token, ca


def _target_deployments() -> list[str]:
    """Список целевых деплойментов из переменной окружения ``AEGIL_UPDATE_DEPLOYMENTS``
    (перечисление через запятую), очищенный от пустых элементов и лишних пробелов. Пустой список
    означает, что владелец не назначил ни одного деплоймента к обновлению, и это безопасное
    состояние по умолчанию: продукт не тронет ничего."""
    raw = _senv("AEGIL_UPDATE_DEPLOYMENTS")
    return [x.strip() for x in raw.split(",") if x.strip()]


def _target_namespace() -> str:
    """Пространство имён, в котором расположены обновляемые деплойменты. Берётся из
    ``AEGIL_NAMESPACE``, а при его отсутствии из ``config.NAMESPACE``, чтобы поведение
    совпадало с остальными управляющими операциями продукта."""
    return _senv("AEGIL_NAMESPACE") or config.NAMESPACE


def _retag(image: str, new_tag: str) -> str:
    """Заменяет тег в ссылке на образ, сохраняя реестр и имя образа неизменными.

    Ссылка на образ имеет форму ``[реестр[:порт]/]имя[:тег][@digest]``. Меняется только тег,
    следующий за последним двоеточием в части имени: двоеточие порта реестра (например
    ``registry:5000/app``) при этом не затрагивается, потому что за ним следует косая черта.
    Существующий фиксирующий дайджест (после ``@``) считается несовместимым с переводом на новый
    тег и удаляется, поскольку продукт выпускается тегами версий, а не дайджестами. Функция не
    предполагает наличия старого тега: образ без тега получает новый тег так же корректно."""
    ref = str(image or "")
    # Дайджест несовместим с переводом на новый тег: отбрасываем его, оставляя часть имени.
    if "@" in ref:
        ref = ref.split("@", 1)[0]
    slash = ref.rfind("/")
    name_part = ref[slash + 1:]
    prefix = ref[:slash + 1] if slash >= 0 else ""
    # Двоеточие в части имени (после последней косой черты) отделяет старый тег, если он есть.
    colon = name_part.rfind(":")
    if colon >= 0:
        name_part = name_part[:colon]
    return f"{prefix}{name_part}:{new_tag}"


def _get_deployment(base, token, ca, ns, name, http):
    """Читает деплоймент через API Kubernetes и возвращает разобранный JSON либо бросает
    исключение, которое перехватывает вызывающая сторона. Клиент инъектируется тем же аргументом
    ``http``, что и в остальных сетевых функциях модуля, ради тестируемости без сети."""
    path = f"{base}/apis/apps/v1/namespaces/{ns}/deployments/{name}"
    headers = {"Authorization": f"Bearer {token}"}
    if http is not None:
        r = http.get(path, headers=headers)
    else:
        with httpx.Client(verify=ca, timeout=_API_TIMEOUT) as cl:
            r = cl.get(path, headers=headers)
    r.raise_for_status()
    return r.json()


def _patch_images(base, token, ca, ns, name, containers, http):
    """Патчит образы контейнеров деплоймента стратегическим слиянием (strategic merge patch).

    Патч перечисляет контейнеры по имени с новым значением поля ``image``; стратегическое слияние
    Kubernetes сопоставляет элементы по ключу ``name``, поэтому меняются только образы, а прочие
    поля контейнеров и деплоймента остаются нетронутыми. Возвращает код состояния ответа API."""
    import json as _json
    body = {"spec": {"template": {"spec": {"containers": containers}}}}
    path = f"{base}/apis/apps/v1/namespaces/{ns}/deployments/{name}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/strategic-merge-patch+json",
    }
    content = _json.dumps(body)
    if http is not None:
        r = http.patch(path, headers=headers, content=content)
    else:
        with httpx.Client(verify=ca, timeout=_API_TIMEOUT) as cl:
            r = cl.patch(path, headers=headers, content=content)
    return r.status_code


def apply(confirmed: bool, operator: str, *, http=None) -> dict:
    """Переводит целевые деплойменты продукта на тег образа из канала обновления. ВЫСОКОРИСКОВО.

    Это высокорисковая мутация инфраструктуры, которая приводит к перекату рабочих нагрузок и
    потому не выполняется автономно ни при каких условиях. Если ``confirmed`` не равно строго
    ``True``, функция немедленно возвращает
    ``{"ok": False, "message": "требуется подтверждение владельца", "needs_confirmation": True}``
    и не совершает никаких действий: не читает канал, не обращается к API Kubernetes, ничего не
    меняет. Подтверждение приходит только от владельца через интерфейс, модель повысить себе
    полномочия не может.

    При ``confirmed=True`` определяется целевой тег образа: сперва читается канал обновления через
    ``check``. Если обновление недоступно (канал недоступен, версия не новее текущей или тег образа
    не сообщён), функция отказывается действовать и возвращает причину, потому что переводить
    деплойменты не на что. Затем перечисляются целевые деплойменты из
    ``AEGIL_UPDATE_DEPLOYMENTS`` в пространстве имён из ``AEGIL_NAMESPACE`` (или
    ``config.NAMESPACE``). Каждый деплоймент читается, у всех его контейнеров тег образа заменяется
    на новый с сохранением реестра и имени образа (меняется строго часть после последнего
    двоеточия в имени), после чего деплоймент патчится стратегическим слиянием. Возвращается отчёт
    по каждому деплойменту с полями ``name``, ``ok`` и ``detail``.

    Вне кластера (при отсутствии токена сервисного аккаунта) функция честно отказывает, сообщая о
    недоступности API Kubernetes, а не падает. Все сетевые обращения выполняются с явными
    таймаутами. Аргумент ``operator`` это идентификатор подтвердившего владельца, он включается в
    отчёт для последующей записи в журнал аудита вызывающей стороной. Аргумент ``http`` это
    необязательный инъектируемый клиент, совместимый по интерфейсу с ``httpx.Client``, для тестов
    без выхода в сеть.

    Замечание о самопатче: если в списке целевых деплойментов присутствует сам деплоймент панели,
    его обновление вызовет перекат панели, что для Kubernetes является штатным поведением; см.
    докстроку модуля."""
    if confirmed is not True:
        return {"ok": False, "message": "требуется подтверждение владельца",
                "needs_confirmation": True}

    info = check(http=http)
    if not info.get("available"):
        return {"ok": False, "operator": operator,
                "message": "обновление недоступно: " + str(
                    info.get("error", "версия в канале не новее текущей")),
                "check": info}
    new_tag = str(info.get("image_tag", "")).strip()
    if not new_tag:
        return {"ok": False, "operator": operator,
                "message": "канал обновления не сообщил тег образа (image_tag)",
                "check": info}

    targets = _target_deployments()
    if not targets:
        return {"ok": False, "operator": operator,
                "message": "не задан ни один целевой деплоймент "
                           "(AEGIL_UPDATE_DEPLOYMENTS пуст)",
                "check": info}

    c = _incluster()
    if c is None:
        return {"ok": False, "operator": operator,
                "message": "вне кластера: нет доступа к API Kubernetes",
                "check": info}
    base, token, ca = c
    ns = _target_namespace()

    report = []
    all_ok = True
    for name in targets:
        if not _NAME_RE.match(name):
            report.append({"name": name, "ok": False,
                           "detail": "недопустимое имя деплоймента"})
            all_ok = False
            continue
        try:
            dep = _get_deployment(base, token, ca, ns, name, http)
        except Exception as e:
            report.append({"name": name, "ok": False,
                           "detail": f"не удалось прочитать деплоймент: {e}"})
            all_ok = False
            continue
        spec_containers = (((dep.get("spec", {}) or {}).get("template", {}) or {}).get(
            "spec", {}) or {}).get("containers", []) or []
        patched = []
        for cont in spec_containers:
            cname = cont.get("name")
            image = cont.get("image", "")
            if not cname or not image:
                continue
            patched.append({"name": cname, "image": _retag(image, new_tag)})
        if not patched:
            report.append({"name": name, "ok": False,
                           "detail": "у деплоймента нет контейнеров с образом"})
            all_ok = False
            continue
        try:
            code = _patch_images(base, token, ca, ns, name, patched, http)
        except Exception as e:
            report.append({"name": name, "ok": False,
                           "detail": f"ошибка вызова API Kubernetes: {e}"})
            all_ok = False
            continue
        if code in (200, 201):
            report.append({"name": name, "ok": True,
                           "detail": f"образы переведены на тег «{new_tag}»"})
        else:
            report.append({"name": name, "ok": False,
                           "detail": f"API Kubernetes вернул {code}"})
            all_ok = False

    return {
        "ok": all_ok,
        "operator": operator,
        "image_tag": new_tag,
        "latest": info.get("latest"),
        "namespace": ns,
        "report": report,
    }
