FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Модули сервиса и статическая оболочка PWA (всё отдаётся самой панелью, внешних адресов нет).
# Копируем все модули шаблоном *.py, а не жёстким перечнем: перечень уже отставал от растущего
# графа импортов (admin_read, admin_mutate, admin_integrations, status, autopilot, guards, alerts),
# из-за чего пересборка падала на старте с ModuleNotFoundError. Шаблон исключает этот класс
# рассинхрона; тестовые файлы попадают в образ безвредно и позволяют прогнать тесты в контейнере.
COPY *.py index.html manifest.webmanifest sw.js icon.svg ./
EXPOSE 9109
# Непривилегированный пользователь (IaC-харден: не от root) плюс писчий каталог под локальные
# копии журнала аудита и ленты инцидентов (сам /app только для чтения под appuser).
RUN useradd -r -u 10002 appuser && mkdir -p /data && chown appuser /data
ENV ADMINCHAT_AUDIT=/data/audit.log.jsonl ADMINCHAT_INCIDENTS=/data/incidents.log.jsonl
USER appuser
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9109"]
