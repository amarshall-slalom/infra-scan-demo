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

CMD ["python", "lambda_function.py"]