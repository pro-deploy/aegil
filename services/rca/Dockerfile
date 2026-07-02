FROM python:3.11-slim
WORKDIR /app
# CPU-колесо torch первым, чтобы setfit не притянул тяжёлую CUDA-сборку (инференс
# rubert-tiny2 идёт на процессоре).
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
ENV HF_HOME=/tmp/.cache/huggingface RCA_SETFIT_DIR=/tmp/setfit-router
# Модули детерминированного ядра и обвязки (без внешних зависимостей у ядра).
COPY normalize.py aggregator.py detectors.py scoring.py verdict.py pipeline.py cache.py router.py cascade.py store.py setfit_model.py report.py loki.py stuck.py app.py ./
EXPOSE 9107
# Непривилегированный пользователь (IaC-харден: не от root).
RUN useradd -r -u 10001 appuser
USER appuser
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9107"]
