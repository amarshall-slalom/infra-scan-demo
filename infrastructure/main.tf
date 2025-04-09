provider "aws" {
  region = "us-west-2"
}

provider "aws" {
  alias  = "replica_region"
  region = "us-east-1" # Using us-east-1 as the replica region
}

variable "vpc_id" {
  description = "VPC ID where resources will be created"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for Lambda function"
  type        = list(string)
}

variable "public_subnet_ids" {
  description = "List of public subnet IDs for ALB"
  type        = list(string)
}

variable "certificate_arn" {
  description = "ARN of ACM certificate for ALB HTTPS listener"
  type        = string
}

# Create KMS key for encryption
resource "aws_kms_key" "encryption_key" {
  description             = "KMS key for encrypting resources"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_ecr_repository" "lambda_repo" {
  name = "demo-lambda-repo"

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.encryption_key.arn
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  image_tag_mutability = "IMMUTABLE"
}

resource "aws_db_instance" "aurora" {
  identifier     = "demo-aurora"
  engine         = "aurora-mysql"
  instance_class = "db.t3.medium"
  username       = "admin"
  password       = aws_secretsmanager_secret_version.db_password.secret_string

  multi_az            = true
  deletion_protection = true
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.encryption_key.arn

  copy_tags_to_snapshot     = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "demo-aurora-final-snapshot"

  auto_minor_version_upgrade = true

  enabled_cloudwatch_logs_exports = ["audit", "error", "general", "slowquery"]

  monitoring_interval = 30
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.encryption_key.arn

  backup_retention_period = 7
}

resource "aws_secretsmanager_secret" "db_password" {
  name       = "demo-aurora-password"
  kms_key_id = aws_kms_key.encryption_key.arn
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db_password.result
}

resource "random_password" "db_password" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Adding rotation configuration for the DB password secret
resource "aws_secretsmanager_secret_rotation" "db_password" {
  secret_id           = aws_secretsmanager_secret.db_password.id
  rotation_lambda_arn = aws_lambda_function.rotation_lambda.arn

  rotation_rules {
    automatically_after_days = 30
  }
}

resource "aws_iam_role" "rds_monitoring" {
  name = "demo-rds-monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_lambda_function" "hello_world" {
  filename      = "../src/lambda_function.zip"
  function_name = "hello-world"
  role          = aws_iam_role.lambda_role.arn
  handler       = "lambda_function.handler"
  runtime       = "python3.9"

  package_type = "Image"
  image_uri    = "${aws_ecr_repository.lambda_repo.repository_url}:latest"

  tracing_config {
    mode = "Active"
  }

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  environment {
    variables = {
      POWERTOOLS_SERVICE_NAME = "hello-world"
      LOG_LEVEL               = "INFO"
    }
  }

  kms_key_arn             = aws_kms_key.encryption_key.arn
  code_signing_config_arn = aws_lambda_code_signing_config.signing_config.arn

  reserved_concurrent_executions = 100
}

resource "aws_lambda_function" "log_processor" {
  filename      = "../src/log_processor.zip"
  function_name = "log-processor"
  role          = aws_iam_role.lambda_role.arn
  handler       = "log_processor.handler"
  runtime       = "python3.9"

  tracing_config {
    mode = "Active"
  }

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  code_signing_config_arn        = aws_lambda_code_signing_config.signing_config.arn
  reserved_concurrent_executions = 50
}

# Add Lambda function for secret rotation
resource "aws_lambda_function" "rotation_lambda" {
  filename      = "../src/rotation_lambda.zip"
  function_name = "secret-rotation"
  role          = aws_iam_role.lambda_role.arn
  handler       = "rotation_lambda.handler"
  runtime       = "python3.9"

  tracing_config {
    mode = "Active"
  }

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  environment {
    variables = {
      SECRETS_MANAGER_ENDPOINT = "https://secretsmanager.${data.aws_region.current.name}.amazonaws.com"
    }
  }

  kms_key_arn                    = aws_kms_key.encryption_key.arn
  code_signing_config_arn        = aws_lambda_code_signing_config.signing_config.arn
  reserved_concurrent_executions = 25
}

resource "aws_lambda_code_signing_config" "signing_config" {
  allowed_publishers {
    signing_profile_version_arns = [aws_signer_signing_profile.lambda_profile.arn]
  }

  policies {
    untrusted_artifact_on_deployment = "Enforce"
  }
}

resource "aws_signer_signing_profile" "lambda_profile" {
  platform_id = "AWSLambda-SHA384-ECDSA"
}

resource "aws_sqs_queue" "dlq" {
  name              = "hello-world-dlq"
  kms_master_key_id = aws_kms_key.encryption_key.id
}

resource "aws_security_group" "lambda_sg" {
  name        = "lambda-sg"
  description = "Security group for Lambda function"
  vpc_id      = var.vpc_id

  egress {
    description = "Allow HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "lambda_role" {
  name = "hello-world-lambda"

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

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_xray" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_lb" "front_end" {
  name               = "demo-lb"
  internal           = false
  load_balancer_type = "application"

  enable_deletion_protection = true
  enable_http2               = true
  drop_invalid_header_fields = true

  subnets         = var.public_subnet_ids
  security_groups = [aws_security_group.alb_sg.id]

  access_logs {
    bucket  = aws_s3_bucket.lb_logs.id
    enabled = true
  }
}

resource "aws_security_group" "alb_sg" {
  name        = "alb-sg"
  description = "Security group for ALB"
  vpc_id      = var.vpc_id

  ingress {
    description = "Allow HTTPS inbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "lb_logs" {
  bucket = "demo-lb-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "lb_logs" {
  bucket = aws_s3_bucket.lb_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "lb_logs" {
  bucket = aws_s3_bucket.lb_logs.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lb_logs" {
  bucket = aws_s3_bucket.lb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.encryption_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "lb_logs" {
  bucket = aws_s3_bucket.lb_logs.id

  rule {
    id     = "default_abort_multipart"
    status = "Enabled"

    filter {
      prefix = "" # Empty prefix applies to all objects
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "lb_logs_lifecycle"
    status = "Enabled"

    filter {
      prefix = "lb-logs/"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_public_access_block" "lb_logs" {
  bucket = aws_s3_bucket.lb_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_replication_configuration" "lb_logs" {
  bucket = aws_s3_bucket.lb_logs.id
  role   = aws_iam_role.replication.arn

  rule {
    id     = "lb_logs_replication"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.lb_logs_replica.arn
      storage_class = "STANDARD_IA"
    }
  }
}

resource "aws_s3_bucket_notification" "lb_logs" {
  bucket = aws_s3_bucket.lb_logs.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.log_processor.arn
    events              = ["s3:ObjectCreated:*"]
  }
}

resource "aws_s3_bucket" "log_bucket" {
  bucket = "demo-lb-logs-logging-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.encryption_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    id     = "default_abort_multipart"
    status = "Enabled"

    filter {
      prefix = "" # Empty prefix applies to all objects
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "log_bucket_lifecycle"
    status = "Enabled"

    filter {
      prefix = "logs/"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_public_access_block" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_notification" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.log_processor.arn
    events              = ["s3:ObjectCreated:*"]
  }
}

resource "aws_s3_bucket_replication_configuration" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id
  role   = aws_iam_role.replication.arn

  rule {
    id     = "log_bucket_replication"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.log_bucket_replica.arn
      storage_class = "STANDARD_IA"
    }
  }
}

resource "aws_s3_bucket" "log_bucket_replica" {
  provider = aws.replica_region
  bucket   = "demo-lb-logs-logging-replica-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lb_logs_replica" {
  provider = aws.replica_region
  bucket   = aws_s3_bucket.lb_logs_replica.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.encryption_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "lb_logs_replica" {
  provider = aws.replica_region
  bucket   = aws_s3_bucket.lb_logs_replica.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "lb_logs_replica" {
  provider = aws.replica_region
  bucket   = aws_s3_bucket.lb_logs_replica.id

  rule {
    id     = "default_abort_multipart"
    status = "Enabled"

    filter {
      prefix = "" # Empty prefix applies to all objects
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "replica_lifecycle"
    status = "Enabled"

    filter {
      prefix = "replica/"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_public_access_block" "lb_logs_replica" {
  provider = aws.replica_region
  bucket   = aws_s3_bucket.lb_logs_replica.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "lb_logs_replica" {
  provider = aws.replica_region
  bucket   = aws_s3_bucket.lb_logs_replica.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "replica-log/"
}

resource "aws_s3_bucket_notification" "lb_logs_replica" {
  provider = aws.replica_region
  bucket   = aws_s3_bucket.lb_logs_replica.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.log_processor.arn
    events              = ["s3:ObjectCreated:*"]
  }
}

resource "aws_s3_bucket" "lb_logs_replica" {
  provider = aws.replica_region
  bucket   = "demo-lb-logs-replica-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_bucket_replica" {
  provider = aws.replica_region
  bucket   = aws_s3_bucket.log_bucket_replica.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.encryption_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "log_bucket_replica" {
  provider = aws.replica_region
  bucket   = aws_s3_bucket.log_bucket_replica.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "log_bucket_replica" {
  provider = aws.replica_region
  bucket   = aws_s3_bucket.log_bucket_replica.id

  rule {
    id     = "default_abort_multipart"
    status = "Enabled"

    filter {
      prefix = "" # Empty prefix applies to all objects
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "replica_lifecycle"
    status = "Enabled"

    filter {
      prefix = "replica-logs/"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_public_access_block" "log_bucket_replica" {
  provider = aws.replica_region
  bucket   = aws_s3_bucket.log_bucket_replica.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "log_bucket_replica" {
  provider = aws.replica_region
  bucket   = aws_s3_bucket.log_bucket_replica.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "replica-logs/"
}

resource "aws_s3_bucket_notification" "log_bucket_replica" {
  provider = aws.replica_region
  bucket   = aws_s3_bucket.log_bucket_replica.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.log_processor.arn
    events              = ["s3:ObjectCreated:*"]
  }
}

resource "aws_iam_role" "replication" {
  name = "s3-bucket-replication"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "replication" {
  name = "s3-bucket-replication-policy"
  role = aws_iam_role.replication.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket"
        ]
        Effect = "Allow"
        Resource = [
          aws_s3_bucket.lb_logs.arn,
          aws_s3_bucket.log_bucket.arn
        ]
      },
      {
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging"
        ]
        Effect = "Allow"
        Resource = [
          "${aws_s3_bucket.lb_logs.arn}/*",
          "${aws_s3_bucket.log_bucket.arn}/*"
        ]
      },
      {
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags"
        ]
        Effect = "Allow"
        Resource = [
          "${aws_s3_bucket.lb_logs_replica.arn}/*",
          "${aws_s3_bucket.log_bucket_replica.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = aws_lb.front_end.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.lambda.arn
  }
}

resource "aws_lb_target_group" "lambda" {
  name        = "lambda-target-group"
  target_type = "lambda"

  health_check {
    enabled             = true
    healthy_threshold   = 3
    interval            = 30
    timeout             = 5
    unhealthy_threshold = 3
  }
}

resource "aws_lb_target_group_attachment" "lambda" {
  target_group_arn = aws_lb_target_group.lambda.arn
  target_id        = aws_lambda_function.hello_world.arn
}

resource "aws_wafv2_web_acl" "main" {
  name        = "demo-waf"
  description = "WAF for ALB"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputsRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "Log4JRCE"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"

        rule_action_override {
          name = "Log4JRCE"
          action_to_use {
            block {}
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "Log4JRCEMetric"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "demo-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "main" {
  resource_arn = aws_lb.front_end.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  log_destination_configs = [aws_kinesis_firehose_delivery_stream.waf_logs.arn]
  resource_arn            = aws_wafv2_web_acl.main.arn
}

resource "aws_s3_bucket" "waf_logs" {
  bucket = "demo-waf-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.encryption_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    id     = "default_abort_multipart"
    status = "Enabled"

    filter {
      prefix = "" # Empty prefix applies to all objects
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "waf_logs_lifecycle"
    status = "Enabled"

    filter {
      prefix = "waf-logs/"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_logging" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "waf-logs/"
}

resource "aws_s3_bucket_notification" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.log_processor.arn
    events              = ["s3:ObjectCreated:*"]
  }
}

resource "aws_s3_bucket_replication_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  role   = aws_iam_role.replication.arn

  rule {
    id     = "waf_logs_replication"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.log_bucket_replica.arn
      storage_class = "STANDARD_IA"
    }
  }
}

resource "aws_kinesis_firehose_delivery_stream" "waf_logs" {
  name        = "aws-waf-logs"
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = aws_kms_key.encryption_key.arn
  }

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = aws_s3_bucket.waf_logs.arn

    buffering_size     = 5
    buffering_interval = 300
    compression_format = "GZIP"

    kms_key_arn = aws_kms_key.encryption_key.arn
  }
}

resource "aws_iam_role" "firehose" {
  name = "waf-logs-firehose"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "firehose" {
  name = "waf-logs-firehose-policy"
  role = aws_iam_role.firehose.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.waf_logs.arn,
          "${aws_s3_bucket.waf_logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [
          aws_kms_key.encryption_key.arn
        ]
      }
    ]
  })
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}