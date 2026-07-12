"""Модульные тесты канала самообновления продукта kube-sentinel (модуль updater).

Тесты собираются стандартным сборщиком pytest (функции с префиксом test_) и выполняются без
обращения к сети: httpx-клиент инъектируется поддельной реализацией через аргумент ``http``, а
контур доступа к API Kubernetes (переменные окружения адреса API-сервера и файлы сервисного
аккаунта) подменяется через фикстуру monkeypatch. Проверяется: семантическое сравнение версий на
краевых случаях (равные, старше, новее, мусор, префикс v), определение текущей версии из окружения
и из файла, проверка канала при доступном обновлении, при отсутствии обновления и при ошибке
канала, отказ ``apply`` без подтверждения владельца без единого действия, честный отказ вне
кластера, успешный патч с подтверждением с проверкой адресов запросов и того, что меняется строго
тег образа при сохранении реестра и имени, а также поведение самопатча деплоймента панели.

Запрещённые правилами проекта символы (длинное тире, стрелка) в текстах не используются.
"""
from __future__ import annotations

import json

import httpx
import pytest

import updater


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


# --- Подделки транспорта httpx -----------------------------------------------------------------


class _FakeResponse:
    """Минимальный ответ httpx: код состояния и тело JSON. Метод raise_for_status повторяет
    поведение httpx, бросая исключение на кодах класса ошибки."""

    def __init__(self, status_code=200, json_body=None):
        self.status_code = status_code
        self._json = json_body if json_body is not None else {}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("ошибка", request=None, response=None)


class _ChannelClient:
    """Поддельный клиент канала обновления: на любой get отдаёт заранее заданный ответ либо бросает
    заранее заданное исключение, фиксируя запрошенный адрес."""

    def __init__(self, response=None, exc=None):
        self.response = response if response is not None else _FakeResponse()
        self.exc = exc
        self.requested = []

    def get(self, url, **kw):
        self.requested.append(url)
        if self.exc is not None:
            raise self.exc
        return self.response


class _ApiClient:
    """Поддельный клиент API Kubernetes: отвечает на get деплойментов заранее заданными телами по
    имени и фиксирует все PATCH-запросы (адрес и разобранное тело) для проверки в тесте."""

    def __init__(self, deployments: dict, patch_status=200):
        # deployments: имя деплоймента -> тело ответа get (структура манифеста деплоймента).
        self._deployments = deployments
        self._patch_status = patch_status
        self.get_calls = []
        self.patch_calls = []  # список (url, разобранное тело патча)

    def get(self, url, **kw):
        self.get_calls.append(url)
        name = url.rsplit("/", 1)[-1]
        body = self._deployments.get(name)
        if body is None:
            return _FakeResponse(status_code=404, json_body={})
        return _FakeResponse(status_code=200, json_body=body)

    def patch(self, url, **kw):
        content = kw.get("content", "{}")
        self.patch_calls.append((url, json.loads(content)))
        return _FakeResponse(status_code=self._patch_status, json_body={})


def _deployment(name: str, containers: list[dict]) -> dict:
    """Собирает минимальное тело деплоймента с заданными контейнерами (имя и образ)."""
    return {
        "metadata": {"name": name},
        "spec": {"template": {"spec": {"containers": containers}}},
    }


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Очищает переменные окружения продукта, влияющие на модуль, перед каждым тестом, чтобы тесты
    не зависели от окружения запуска и друг от друга."""
    for var in ("SENTINEL_VERSION", "SENTINEL_UPDATE_CHANNEL_URL",
                "SENTINEL_UPDATE_DEPLOYMENTS", "SENTINEL_NAMESPACE",
                "KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT"):
        monkeypatch.delenv(var, raising=False)
    yield


def _fake_incluster(monkeypatch, present=True):
    """Подменяет определение контура кластера: при present=True возвращает фиктивный контур
    (адрес, токен, отсутствие проверки сертификата), иначе None, моделируя запуск вне кластера. Так
    ни один тест не зависит от смонтированного сервисного аккаунта."""
    if present:
        monkeypatch.setattr(updater, "_incluster",
                            lambda: ("https://api:6443", "tkn", False))
    else:
        monkeypatch.setattr(updater, "_incluster", lambda: None)


# --- Семантическое сравнение версий ------------------------------------------------------------


def test_parse_semver_edges():
    _eq("простая версия", updater._parse("1.2.3"), (1, 2, 3))
    _eq("префикс v игнорируется", updater._parse("v1.2.3"), (1, 2, 3))
    _eq("нули", updater._parse("0.0.0"), (0, 0, 0))
    _eq("хвост отбрасывается", updater._parse("1.2.3-rc1"), (1, 2, 3))
    _eq("метаданные сборки отбрасываются", updater._parse("1.2.3+build.7"), (1, 2, 3))
    _eq("пустая строка не версия", updater._parse(""), None)
    _eq("мусор не версия", updater._parse("не версия"), None)
    _eq("две компоненты не версия", updater._parse("1.2"), None)
    _eq("None не версия", updater._parse(None), None)


def test_newer_edges():
    _eq("новее по патчу", updater._newer("1.2.4", "1.2.3"), True)
    _eq("новее по минору", updater._newer("1.3.0", "1.2.9"), True)
    _eq("новее по мажору", updater._newer("2.0.0", "1.9.9"), True)
    _eq("равные не новее", updater._newer("1.2.3", "1.2.3"), False)
    _eq("равные с префиксом v", updater._newer("v1.2.3", "1.2.3"), False)
    _eq("старее не новее", updater._newer("1.2.2", "1.2.3"), False)
    _eq("мусор слева не новее", updater._newer("мусор", "1.2.3"), False)
    _eq("мусор справа не новее", updater._newer("1.2.3", "мусор"), False)
    # Числовое, а не лексикографическое сравнение компонентов.
    _eq("десять новее девяти", updater._newer("1.10.0", "1.9.0"), True)


# --- Текущая версия продукта -------------------------------------------------------------------


def test_current_version_from_env(monkeypatch):
    monkeypatch.setenv("SENTINEL_VERSION", "3.4.5")
    _eq("версия из окружения", updater.current_version(), "3.4.5")


def test_current_version_from_file(monkeypatch, tmp_path):
    # Переменная окружения не задана: версия читается из файла VERSION рядом с модулем.
    vfile = tmp_path / "VERSION"
    vfile.write_text("2.1.0\n", encoding="utf-8")
    monkeypatch.setattr(updater, "_VERSION_FILE", str(vfile))
    _eq("версия из файла", updater.current_version(), "2.1.0")


def test_current_version_default(monkeypatch):
    # Ни окружения, ни файла: нейтральное значение, заведомо старше любой выпущенной версии.
    monkeypatch.setattr(updater, "_VERSION_FILE", "/nonexistent/VERSION")
    _eq("версия по умолчанию", updater.current_version(), "0.0.0")


# --- Проверка канала обновления ----------------------------------------------------------------


def test_check_update_available(monkeypatch):
    monkeypatch.setenv("SENTINEL_VERSION", "1.0.0")
    monkeypatch.setenv("SENTINEL_UPDATE_CHANNEL_URL", "https://updates.example/latest.json")
    client = _ChannelClient(_FakeResponse(json_body={
        "version": "1.1.0", "image_tag": "1.1.0", "notes": "новые возможности"}))
    res = updater.check(http=client)
    _eq("обращение строго по настроенному адресу",
        client.requested, ["https://updates.example/latest.json"])
    _eq("текущая версия", res["current"], "1.0.0")
    _eq("версия из канала", res["latest"], "1.1.0")
    _eq("тег образа", res["image_tag"], "1.1.0")
    _eq("обновление доступно", res["available"], True)
    _eq("примечания", res["notes"], "новые возможности")


def test_check_no_update(monkeypatch):
    monkeypatch.setenv("SENTINEL_VERSION", "1.1.0")
    monkeypatch.setenv("SENTINEL_UPDATE_CHANNEL_URL", "https://updates.example/latest.json")
    client = _ChannelClient(_FakeResponse(json_body={
        "version": "1.1.0", "image_tag": "1.1.0"}))
    res = updater.check(http=client)
    _eq("обновления нет при равной версии", res["available"], False)
    _eq("текущая версия видна", res["current"], "1.1.0")


def test_check_channel_error(monkeypatch):
    monkeypatch.setenv("SENTINEL_VERSION", "1.0.0")
    monkeypatch.setenv("SENTINEL_UPDATE_CHANNEL_URL", "https://updates.example/latest.json")
    client = _ChannelClient(exc=httpx.ConnectError("нет связи"))
    res = updater.check(http=client)
    _eq("ошибка канала мягко деградирует", res["available"], False)
    assert "error" in res, res
    assert "недоступен" in res["error"], res["error"]


def test_check_channel_not_configured(monkeypatch):
    # Адрес канала не настроен: честный отказ без обращения в сеть.
    res = updater.check()
    _eq("канал не настроен", res["available"], False)
    assert "не настроен" in res["error"], res["error"]


def test_check_channel_bad_body(monkeypatch):
    monkeypatch.setenv("SENTINEL_UPDATE_CHANNEL_URL", "https://updates.example/latest.json")
    client = _ChannelClient(_FakeResponse(json_body=["не", "словарь"]))
    res = updater.check(http=client)
    _eq("некорректное тело мягко деградирует", res["available"], False)
    assert "некорректный" in res["error"], res["error"]


def test_check_channel_no_version(monkeypatch):
    monkeypatch.setenv("SENTINEL_UPDATE_CHANNEL_URL", "https://updates.example/latest.json")
    client = _ChannelClient(_FakeResponse(json_body={"image_tag": "1.2.3"}))
    res = updater.check(http=client)
    _eq("отсутствие версии в канале", res["available"], False)
    assert "не сообщил версию" in res["error"], res["error"]


# --- Применение обновления: подтверждение ------------------------------------------------------


def test_apply_without_confirmation_does_nothing(monkeypatch):
    # Даже при полностью настроенном контуре без подтверждения не делается НИЧЕГО.
    monkeypatch.setenv("SENTINEL_UPDATE_CHANNEL_URL", "https://updates.example/latest.json")
    monkeypatch.setenv("SENTINEL_UPDATE_DEPLOYMENTS", "agent-panel")
    _fake_incluster(monkeypatch, present=True)
    # Клиент, который упал бы при любом обращении: доказывает, что сеть не трогается.
    client = _ChannelClient(exc=AssertionError("канал не должен запрашиваться без подтверждения"))
    res = updater.apply(False, "alice", http=client)
    _eq("без подтверждения не ок", res["ok"], False)
    _eq("требуется подтверждение", res["needs_confirmation"], True)
    _eq("сеть не тронута", client.requested, [])
    assert "подтверждение" in res["message"], res["message"]


def test_apply_confirmed_must_be_true_not_truthy(monkeypatch):
    # Проверка строго на True: истиноподобные значения не считаются подтверждением.
    res = updater.apply(1, "alice")
    _eq("единица не подтверждение", res.get("needs_confirmation"), True)
    res = updater.apply("yes", "alice")
    _eq("строка не подтверждение", res.get("needs_confirmation"), True)


# --- Применение обновления: вне кластера -------------------------------------------------------


def test_apply_outside_cluster_honest_refusal(monkeypatch):
    monkeypatch.setenv("SENTINEL_VERSION", "1.0.0")
    monkeypatch.setenv("SENTINEL_UPDATE_CHANNEL_URL", "https://updates.example/latest.json")
    monkeypatch.setenv("SENTINEL_UPDATE_DEPLOYMENTS", "agent-panel")
    _fake_incluster(monkeypatch, present=False)
    client = _ChannelClient(_FakeResponse(json_body={"version": "1.1.0", "image_tag": "1.1.0"}))
    res = updater.apply(True, "alice", http=client)
    _eq("вне кластера не ок", res["ok"], False)
    assert "вне кластера" in res["message"], res["message"]


# --- Применение обновления: успешный патч ------------------------------------------------------


def test_apply_confirmed_patches_only_tag(monkeypatch):
    monkeypatch.setenv("SENTINEL_VERSION", "1.0.0")
    monkeypatch.setenv("SENTINEL_UPDATE_CHANNEL_URL", "https://updates.example/latest.json")
    monkeypatch.setenv("SENTINEL_UPDATE_DEPLOYMENTS", "agent-panel, rca")
    monkeypatch.setenv("SENTINEL_NAMESPACE", "sentinel")
    _fake_incluster(monkeypatch, present=True)

    # check() ходит своим клиентом канала; API ходит своим. Разделяем их подменой check.
    monkeypatch.setattr(updater, "check", lambda *, http=None: {
        "current": "1.0.0", "latest": "1.1.0", "image_tag": "1.1.0", "available": True})

    api = _ApiClient({
        "agent-panel": _deployment("agent-panel", [
            {"name": "panel", "image": "registry.example:5000/sentinel/agent-panel:1.0.0"}]),
        "rca": _deployment("rca", [
            {"name": "rca", "image": "ghcr.io/acme/rca:v1.0.0"}]),
    })
    res = updater.apply(True, "alice", http=api)

    _eq("общий успех", res["ok"], True)
    _eq("оператор в отчёте", res["operator"], "alice")
    _eq("пространство имён", res["namespace"], "sentinel")
    _eq("два деплоймента в отчёте", len(res["report"]), 2)
    assert all(item["ok"] for item in res["report"]), res["report"]

    # PATCH ушёл на правильные адреса обоих деплойментов в правильном пространстве имён.
    patched_urls = [u for (u, _b) in api.patch_calls]
    _eq("два PATCH", len(patched_urls), 2)
    assert "https://api:6443/apis/apps/v1/namespaces/sentinel/deployments/agent-panel" \
        in patched_urls, patched_urls
    assert "https://api:6443/apis/apps/v1/namespaces/sentinel/deployments/rca" \
        in patched_urls, patched_urls

    # Меняется строго тег: реестр (включая порт) и имя образа сохранены.
    by_url = {u: b for (u, b) in api.patch_calls}
    panel_body = by_url[
        "https://api:6443/apis/apps/v1/namespaces/sentinel/deployments/agent-panel"]
    panel_image = panel_body["spec"]["template"]["spec"]["containers"][0]["image"]
    _eq("реестр с портом и имя сохранены, тег заменён",
        panel_image, "registry.example:5000/sentinel/agent-panel:1.1.0")

    rca_body = by_url["https://api:6443/apis/apps/v1/namespaces/sentinel/deployments/rca"]
    rca_image = rca_body["spec"]["template"]["spec"]["containers"][0]["image"]
    _eq("реестр и имя сохранены, тег заменён", rca_image, "ghcr.io/acme/rca:1.1.0")


def test_apply_self_patch_of_panel(monkeypatch):
    # Самопатч: панель в списке целевых деплойментов, её образ переводится на новый тег штатно.
    monkeypatch.setenv("SENTINEL_UPDATE_CHANNEL_URL", "https://updates.example/latest.json")
    monkeypatch.setenv("SENTINEL_UPDATE_DEPLOYMENTS", "agent-panel")
    monkeypatch.setenv("SENTINEL_NAMESPACE", "sentinel")
    _fake_incluster(monkeypatch, present=True)
    monkeypatch.setattr(updater, "check", lambda *, http=None: {
        "current": "1.0.0", "latest": "2.0.0", "image_tag": "2.0.0", "available": True})
    api = _ApiClient({
        "agent-panel": _deployment("agent-panel", [
            {"name": "panel", "image": "registry.example/sentinel/agent-panel:1.0.0"}]),
    })
    res = updater.apply(True, "owner", http=api)
    _eq("самопатч успешен", res["ok"], True)
    _, body = api.patch_calls[0]
    image = body["spec"]["template"]["spec"]["containers"][0]["image"]
    _eq("образ панели переведён на новый тег",
        image, "registry.example/sentinel/agent-panel:2.0.0")


def test_apply_unavailable_update_refuses(monkeypatch):
    # Обновление недоступно (нет новее версии): apply не трогает API даже с подтверждением.
    monkeypatch.setenv("SENTINEL_UPDATE_DEPLOYMENTS", "agent-panel")
    _fake_incluster(monkeypatch, present=True)
    monkeypatch.setattr(updater, "check", lambda *, http=None: {
        "current": "1.1.0", "latest": "1.1.0", "image_tag": "1.1.0", "available": False})
    api = _ApiClient({})
    res = updater.apply(True, "alice", http=api)
    _eq("нет обновления не ок", res["ok"], False)
    _eq("API не тронут", api.patch_calls, [])
    assert "недоступно" in res["message"], res["message"]


def test_apply_no_targets_refuses(monkeypatch):
    # Обновление есть, но целевые деплойменты не заданы: ничего не патчится.
    _fake_incluster(monkeypatch, present=True)
    monkeypatch.setattr(updater, "check", lambda *, http=None: {
        "current": "1.0.0", "latest": "1.1.0", "image_tag": "1.1.0", "available": True})
    api = _ApiClient({})
    res = updater.apply(True, "alice", http=api)
    _eq("без целей не ок", res["ok"], False)
    _eq("API не тронут", api.patch_calls, [])
    assert "целевой деплоймент" in res["message"], res["message"]


def test_apply_no_image_tag_refuses(monkeypatch):
    # Канал сообщил о доступном обновлении, но без тега образа: переводить не на что.
    monkeypatch.setenv("SENTINEL_UPDATE_DEPLOYMENTS", "agent-panel")
    _fake_incluster(monkeypatch, present=True)
    monkeypatch.setattr(updater, "check", lambda *, http=None: {
        "current": "1.0.0", "latest": "1.1.0", "image_tag": "", "available": True})
    api = _ApiClient({})
    res = updater.apply(True, "alice", http=api)
    _eq("без тега образа не ок", res["ok"], False)
    _eq("API не тронут", api.patch_calls, [])
    assert "тег образа" in res["message"], res["message"]


def test_apply_partial_failure_reported(monkeypatch):
    # Один деплоймент патчится, другой недоступен: общий ok=False, но успех первого зафиксирован.
    monkeypatch.setenv("SENTINEL_UPDATE_DEPLOYMENTS", "agent-panel, missing")
    monkeypatch.setenv("SENTINEL_NAMESPACE", "sentinel")
    _fake_incluster(monkeypatch, present=True)
    monkeypatch.setattr(updater, "check", lambda *, http=None: {
        "current": "1.0.0", "latest": "1.1.0", "image_tag": "1.1.0", "available": True})
    api = _ApiClient({
        "agent-panel": _deployment("agent-panel", [
            {"name": "panel", "image": "acme/agent-panel:1.0.0"}]),
        # деплоймент missing отсутствует, его get вернёт 404
    })
    res = updater.apply(True, "alice", http=api)
    _eq("частичный сбой это общий не ок", res["ok"], False)
    report = {item["name"]: item for item in res["report"]}
    _eq("панель обновлена", report["agent-panel"]["ok"], True)
    _eq("отсутствующий деплоймент не обновлён", report["missing"]["ok"], False)
    # Патч ушёл только по существующему деплойменту.
    _eq("ровно один PATCH", len(api.patch_calls), 1)


def test_retag_variants():
    # Прямые проверки перетегирования на краевых формах ссылки на образ.
    _eq("реестр с портом", updater._retag("reg:5000/app:1.0.0", "2.0.0"), "reg:5000/app:2.0.0")
    _eq("без тега", updater._retag("acme/app", "2.0.0"), "acme/app:2.0.0")
    _eq("голое имя", updater._retag("app:1.0.0", "2.0.0"), "app:2.0.0")
    _eq("дайджест отбрасывается",
        updater._retag("acme/app@sha256:abcd", "2.0.0"), "acme/app:2.0.0")
    _eq("реестр с портом без тега",
        updater._retag("reg:5000/app", "2.0.0"), "reg:5000/app:2.0.0")
