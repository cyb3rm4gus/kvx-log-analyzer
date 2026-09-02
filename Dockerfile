# syntax=docker/dockerfile:1
# ---- build ----------------------------------------------------------------
FROM python:3.12-slim AS build
WORKDIR /app
COPY requirements.txt .
# --require-hashes fails closed: a tampered or substituted wheel aborts the build.
RUN pip install --no-cache-dir --require-hashes -r requirements.txt --target /install

# ---- runtime --------------------------------------------------------------
FROM python:3.12-slim
RUN useradd --system --uid 10001 --no-create-home loganalyzer
WORKDIR /app
# The SQLite file lives here; chowned so the named volume inherits uid 10001.
RUN mkdir -p /data && chown 10001:10001 /data
VOLUME /data
COPY --from=build /install /usr/local/lib/python3.12/site-packages
COPY src/ ./src/
ENV PYTHONPATH=/app/src PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 LA_DB_PATH=/data/loganalyzer.sqlite
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=12 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"]
CMD ["python", "-m", "uvicorn", "loganalyzer.main:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
