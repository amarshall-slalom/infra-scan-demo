FROM python:3.9-slim

LABEL maintainer="demo@example.com"

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl=7.74.0-* && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/lambda_function.py .

RUN useradd -r -s /bin/false appuser && \
    chown appuser:appuser /app

USER appuser

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

CMD ["python", "lambda_function.py"]