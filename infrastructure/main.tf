provider "aws" {
  region = "us-west-2"
}

resource "aws_ecr_repository" "lambda_repo" {
  name = "demo-lambda-repo"
  # Intentionally not using encryption
  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_db_instance" "aurora" {
  identifier           = "demo-aurora"
  engine              = "aurora-mysql"
  instance_class      = "db.t3.medium"
  username            = "admin"
  password            = "insecure123"  # Intentionally insecure
  skip_final_snapshot = true
  # Intentionally not encrypting storage
  storage_encrypted   = false
}

resource "aws_lambda_function" "hello_world" {
  filename         = "../src/lambda_function.zip"
  function_name    = "hello-world"
  role            = aws_iam_role.lambda_role.arn
  handler         = "lambda_function.handler"
  runtime         = "python3.9"

  package_type    = "Image"
  image_uri       = "${aws_ecr_repository.lambda_repo.repository_url}:latest"
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
  name               = "demo-lb"
  internal           = false
  load_balancer_type = "application"
  
  # Intentionally not using HTTPS
  enable_http2       = true
  
  subnets = ["subnet-12345678", "subnet-87654321"]  # Example subnet IDs
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = aws_lb.front_end.arn
  port              = "80"  # Intentionally using HTTP
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.lambda.arn
  }
}