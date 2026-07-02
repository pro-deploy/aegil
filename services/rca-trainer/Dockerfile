FROM python:3.11-slim
WORKDIR /app
# CPU-колесо torch ставим первым, чтобы setfit не притянул тяжёлую CUDA-сборку
# (обучение rubert-tiny2 идёт на процессоре, не конкурируя с vLLM за видеопамять).
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY train.py .
# Инструмент разового засева холодного старта и сам датасет (ADR-0041): seed_load.py вставляет
# размеченные примеры в rca_route_examples, тренер затем обучает на них SetFit.
COPY seed_load.py seed_dataset.jsonl ./
# Кэш моделей во временный каталог (непривилегированный пользователь).
ENV HF_HOME=/tmp/.cache/huggingface
RUN useradd -r -u 10001 appuser
USER appuser
CMD ["python", "train.py"]
