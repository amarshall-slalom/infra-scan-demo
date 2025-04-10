# checkov:skip=CKV_DOCKER_6: Intentionally using deprecated MAINTAINER for demo
# checkov:skip=CKV_DOCKER_8: Intentionally using root user for demo
# checkov:skip=CKV_DOCKER_2: Intentionally omitting HEALTHCHECK for demo
# Intentionally introducing hadolint issues for demo purposes:
# Intentionally insecure/non-optimal Dockerfile for demo purposes
FROM python:3.9

MAINTAINER demo@example.com

RUN apt-get update
RUN apt-get install -y curl

COPY ../src/lambda_function.py .

USER root
CMD ["python", "lambda_function.py"]