mock_provider "aws" {
}

mock_provider "aws" {
  alias                       = "replica_region"
}

variables {
  vpc_id = "vpc-12345678"
  private_subnet_ids = ["subnet-12345678", "subnet-87654321"]
  public_subnet_ids = ["subnet-11111111", "subnet-22222222"]
  certificate_arn = "arn:aws:acm:us-west-2:123456789012:certificate/12345678-1234-1234-1234-123456789012"
}

run "verify_s3_bucket_security" {
  command = plan

  assert {
    condition = (
      contains([for config in aws_s3_bucket_versioning.lb_logs.versioning_configuration : config.status],
      "Enabled")
    )
    error_message = "S3 bucket versioning must be enabled"
  }

  assert {
    condition = anytrue([
      for rule in aws_s3_bucket_server_side_encryption_configuration.lb_logs.rule : 
      rule.apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
    ])
    error_message = "S3 bucket must use KMS encryption"
  }

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.lb_logs.block_public_acls,
      aws_s3_bucket_public_access_block.lb_logs.block_public_policy,
      aws_s3_bucket_public_access_block.lb_logs.ignore_public_acls,
      aws_s3_bucket_public_access_block.lb_logs.restrict_public_buckets
    ])
    error_message = "S3 bucket must block all public access"
  }
}

run "verify_waf_rules" {
  command = plan

  assert {
    condition = anytrue([
      for rule in aws_wafv2_web_acl.main.rule :
      rule.name == "AWSManagedRulesCommonRuleSet"
    ])
    error_message = "WAF must include AWSManagedRulesCommonRuleSet"
  }

  assert {
    condition = length(aws_wafv2_web_acl_logging_configuration.main.log_destination_configs) > 0
    error_message = "WAF logging must be enabled"
  }
}

run "verify_lambda_security" {
  command = plan

  assert {
    condition = length(aws_lambda_function.hello_world.vpc_config) > 0
    error_message = "Lambda function must have VPC configuration"
  }

  assert {
    condition = length(aws_lambda_function.hello_world.tracing_config) > 0
    error_message = "Lambda function must have tracing configuration"
  }
}

run "verify_alb_security" {
  command = plan

  assert {
    condition = alltrue([
      aws_lb_listener.front_end.protocol == "HTTPS",
      aws_lb_listener.front_end.ssl_policy == "ELBSecurityPolicy-TLS-1-2-2017-01"
    ])
    error_message = "ALB listener must use HTTPS with TLS 1.2"
  }

  assert {
    condition = alltrue([
      aws_lb.front_end.enable_deletion_protection,
      aws_lb.front_end.drop_invalid_header_fields,
      anytrue([for config in aws_lb.front_end.access_logs : config.enabled])
    ])
    error_message = "ALB must have proper security configurations"
  }
}