FROM python:3.11-slim
WORKDIR /app
# Колесо torch (CPU) ставим первым и с запиненной версией, чтобы setfit не притянул
# тяжёлую сборку с поддержкой CUDA (обучение rubert-tiny2 идёт на процессоре) и чтобы
# сборка образа была воспроизводимой: по одному тегу образа всегда ясен точный torch.
RUN pip install --no-cache-dir torch==2.4.1 --index-url https://download.pytorch.org/whl/cpu
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY train.py .
# Инструмент разового засева холодного старта и сам датасет: seed_load.py вставляет
# размеченные примеры в rca_route_examples, тренер затем обучает на них SetFit.
COPY seed_load.py seed_dataset.jsonl ./
# Кэш моделей во временный каталог (непривилегированный пользователь).
ENV HF_HOME=/tmp/.cache/huggingface
RUN useradd -r -u 10001 appuser
USER appuser
CMD ["python", "train.py"]
