provider "aws" {
  region = "us-west-2"
}

resource "aws_ecr_repository" "lambda_repo" {
  name = "demo-lambda-repo"
  # checkov:skip=CKV_AWS_163: Intentionally disabled scan on push for demo
  # checkov:skip=CKV_AWS_136: Intentionally using AES256 instead of KMS for demo
  # checkov:skip=CKV_AWS_51: Intentionally allowing mutable tags for demo
  # Intentionally not using encryption
  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_db_instance" "aurora" {
  # checkov:skip=CKV_AWS_293: Intentionally disabled deletion protection for demo
  # checkov:skip=CKV_AWS_353: Intentionally disabled performance insights for demo
  # checkov:skip=CKV_AWS_157: Intentionally disabled Multi-AZ for demo
  # checkov:skip=CKV_AWS_129: Intentionally disabled logging for demo
  # checkov:skip=CKV_AWS_226: Intentionally disabled auto minor version upgrades for demo
  # checkov:skip=CKV_AWS_118: Intentionally disabled enhanced monitoring for demo
  # checkov:skip=CKV_AWS_16: Intentionally disabled storage encryption for demo
  # checkov:skip=CKV2_AWS_60: Intentionally disabled copy tags to snapshots for demo
  identifier          = "demo-aurora"
  engine              = "aurora-mysql"
  instance_class      = "db.t3.medium"
  username            = "admin"
  password            = "insecure123" # Intentionally insecure
  # checkov:skip=CKV_SECRET_6: Intentionally insecure
  skip_final_snapshot = true
  # Intentionally not encrypting storage
  storage_encrypted = false
}

resource "aws_lambda_function" "hello_world" {
  # checkov:skip=CKV_AWS_50: Intentionally disabled X-Ray tracing for demo
  # checkov:skip=CKV_AWS_117: Intentionally not using VPC for demo
  # checkov:skip=CKV_AWS_116: Intentionally not using DLQ for demo
  # checkov:skip=CKV_AWS_272: Intentionally disabled code signing for demo
  # checkov:skip=CKV_AWS_115: Intentionally not setting concurrency limits for demo
  filename      = "../src/lambda_function.zip"
  function_name = "hello-world"
  role          = aws_iam_role.lambda_role.arn
  handler       = "lambda_function.handler"
  runtime       = "python3.9"

  package_type = "Image"
  image_uri    = "${aws_ecr_repository.lambda_repo.repository_url}:latest"
}

resource "aws_iam_role" "lambda_role" {
  name = "demo-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_lb" "front_end" {
  # checkov:skip=CKV_AWS_150: Intentionally disabled deletion protection for demo
  # checkov:skip=CKV_AWS_91: Intentionally disabled access logging for demo
  # checkov:skip=CKV_AWS_131: Intentionally not dropping HTTP headers for demo
  # checkov:skip=CKV2_AWS_20: Intentionally not redirecting HTTP to HTTPS for demo
  # checkov:skip=CKV2_AWS_28: Intentionally not using WAF for demo
  name               = "demo-lb"
  internal           = false
  load_balancer_type = "application"

  # Intentionally not using HTTPS
  enable_http2 = true

  subnets = ["subnet-12345678", "subnet-87654321"] # Example subnet IDs
}

resource "aws_lb_target_group" "lambda" {
  # checkov:skip=CKV_AWS_261: Intentionally not defining healthcheck for demo
  # checkov:skip=CKV_AWS_378: Intentionally using HTTP protocol for demo
  name        = "demo-lambda-tg"
  target_type = "lambda"
  port        = 80
  protocol    = "HTTP"  # Intentionally using HTTP for demo
  vpc_id      = "vpc-12345678"  # Example VPC ID
}

resource "aws_lb_target_group_attachment" "lambda" {
  target_group_arn = aws_lb_target_group.lambda.arn
  target_id        = aws_lambda_function.hello_world.arn
}

resource "aws_lb_listener" "front_end" {
  # checkov:skip=CKV_AWS_2: Intentionally using HTTP protocol for demo
  # checkov:skip=CKV_AWS_103: Intentionally not using TLS for demo
  load_balancer_arn = aws_lb.front_end.arn
  port              = "80" # Intentionally using HTTP
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.lambda.arn
  }
}