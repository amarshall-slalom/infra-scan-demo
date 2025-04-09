# Security Linting Demo Project

This project demonstrates the use of two powerful security linting tools: Checkov and Hadolint. It includes intentionally misconfigured infrastructure and container code to showcase how these tools can identify security issues and best practice violations.

## Project Overview

The project consists of:
- A simple Lambda function that returns "Hello World"
- Infrastructure as Code (Terraform) to deploy the Lambda with associated AWS resources
- A Dockerfile to containerize the Lambda function
- GitHub Actions workflow that runs security checks

## About the Tools

### Checkov

Checkov is an Infrastructure as Code (IaC) static analysis tool. It scans cloud infrastructure configurations to find misconfigurations that may lead to security or compliance issues. Key features:

- Supports multiple IaC frameworks (Terraform, CloudFormation, Kubernetes, etc.)
- 1000+ built-in policies covering security & compliance best practices
- Custom policy support using Python
- CI/CD integration
- Auto-fix capabilities for common issues

In this project, Checkov identifies several intentional security issues in our Terraform code, such as:
- Unencrypted RDS storage
- HTTP-only load balancer configuration
- Missing security features in Lambda configuration
- Basic ECR security settings

### Hadolint

Hadolint is a Dockerfile linter that helps you build best practice Docker images. It works by:

- Analyzing Dockerfile syntax
- Validating shell commands in RUN instructions
- Implementing Docker best practices
- Catching common mistakes and security issues

In our demo, Hadolint catches several intentional issues:
- Use of deprecated instructions
- Inefficient layer management
- Security concerns like running as root
- Image tag best practices

## Running the Demo

The project includes a GitHub Actions workflow that runs both tools in parallel. On each push or pull request:

1. Checkov scans the Terraform files in the `infrastructure/` directory
2. Hadolint analyzes the Dockerfile in the `docker/` directory

Both tools will report their findings, making it easy to understand how they detect security issues and best practice violations.

## Purpose

This project serves as an educational tool to:
- Demonstrate the importance of security scanning in IaC and container workflows
- Show how automated tools can catch security issues early
- Provide examples of common security misconfigurations
- Illustrate the integration of security scanning in CI/CD pipelines

Note: The security issues in this project are intentional for demonstration purposes. In a real project, you should address these issues according to your security requirements.