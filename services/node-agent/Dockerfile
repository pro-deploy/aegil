# Крошечный образ node-agent (ADR-0041): чистый Python-stdlib-сервер без внешних зависимостей.
# Единственная системная добавка это util-linux, откуда берётся nsenter для входа в пространство
# имён хоста. Никаких pip-пакетов, поэтому образ остаётся минимальным.
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends util-linux \
    && rm -rf /var/lib/apt/lists/*
# Копируем только модуль сервиса и его тесты (тесты безвредно попадают в образ и позволяют прогон
# внутри контейнера). Внешних зависимостей и requirements.txt нет.
COPY app.py test_node_agent.py ./
EXPOSE 9110
# Пользователя не понижаем: сервис по назначению привилегированный и через nsenter входит в
# пространство хоста с PID 1, для чего под запускается как privileged (см. манифест DaemonSet).
CMD ["python", "app.py"]
