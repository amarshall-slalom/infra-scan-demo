FROM python:3.9
MAINTAINER demo@example.com

RUN apt-get update
RUN apt-get install -y curl

COPY ../src/lambda_function.py .

USER root
CMD ["python", "lambda_function.py"]