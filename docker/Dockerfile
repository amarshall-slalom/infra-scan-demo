# checkov:skip=CKV_DOCKER_6: Intentionally using deprecated MAINTAINER for demo
# checkov:skip=CKV_DOCKER_8: Intentionally using root user for demo
# checkov:skip=CKV_DOCKER_2: Intentionally omitting HEALTHCHECK for demo
# Intentionally introducing hadolint issues for demo purposes:
# Intentionally insecure/non-optimal Dockerfile for demo purposes
FROM python:3.9

# hadolint ignore=DL4000
MAINTAINER demo@example.com

# hadolint ignore=DL3059,DL3009
RUN apt-get update
# hadolint ignore=DL3015,DL3008,DL3059,DL3009
RUN apt-get install -y curl

# hadolint ignore=DL3045
COPY ../src/lambda_function.py .

# hadolint ignore=DL3002
USER root
CMD ["python", "lambda_function.py"]