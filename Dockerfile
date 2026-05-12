FROM python:3.12-slim

WORKDIR /app

RUN pip install uv

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN uv pip install --system .

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["mcp-opnsense"]
