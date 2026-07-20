# Build stage: resolve and install dependencies into a self-contained venv.
FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /usr/local/bin/uv

WORKDIR /src
COPY pyproject.toml ./
COPY avanza_mcp ./avanza_mcp

RUN uv venv /opt/venv \
    && VIRTUAL_ENV=/opt/venv uv pip install --no-cache .

# Runtime stage: no build tooling, no uv, no source tree.
FROM python:3.12-slim

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Run as an unprivileged user. Combined with --read-only, --cap-drop ALL and
# --security-opt no-new-privileges in the launcher, the container has no write
# access to anything but the tmpfs mounted at /tmp.
RUN useradd --system --uid 10001 --no-create-home appuser
USER appuser

# stdio transport: the MCP protocol runs over stdin/stdout, so no port is exposed
# and nothing may be written to stdout other than protocol frames.
ENTRYPOINT ["python", "-m", "avanza_mcp.server"]
