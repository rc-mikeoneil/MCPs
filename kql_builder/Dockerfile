# syntax=docker/dockerfile:1.7
FROM python:3.12-slim

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_USER=app \
    APP_UID=10001 \
    APP_GID=10001 \
    APP_HOME=/app \
    CACHE_DIR=/app/.cache

# Minimal system deps (TLS certs, curl for debug, git for potential future installs, socat for TCP bridge)
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git socat \
    && rm -rf /var/lib/apt/lists/*

# Non-root user & app dir
RUN groupadd -g ${APP_GID} ${APP_USER} \
 && useradd -m -u ${APP_UID} -g ${APP_GID} -s /usr/sbin/nologin ${APP_USER} \
 && mkdir -p ${APP_HOME} ${CACHE_DIR}
WORKDIR ${APP_HOME}

# --- Python deps (FastMCP + your stack) ---
COPY requirements.txt ./
RUN python -m pip install --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt && \
    python - <<'PY'
import fastmcp, pydantic, rapidfuzz
print("Deps OK. FastMCP:", getattr(fastmcp, "__version__", "unknown"))
PY

# App source
COPY server.py schema_scraper.py kql_builder.py README.md ./
COPY defender_xdr_kql_schema_fuller ./defender_xdr_kql_schema_fuller

# Entrypoint
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh && \
    chown -R ${APP_UID}:${APP_GID} ${APP_HOME}

USER ${APP_UID}:${APP_GID}

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD test -w ${CACHE_DIR} || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
# stdio mode by default (FastMCP)
CMD ["python", "server.py"]
