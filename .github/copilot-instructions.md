<!-- Use this file to provide workspace-specific custom instructions to Copilot -->

# Project Context

This is a demo project for security linting tools, specifically:
- Checkov for infrastructure-as-code security scanning
- Hadolint for Docker best practices and security scanning

## Project Structure
- `docker/` - Contains Dockerfile with intentional issues for Hadolint demo
- `infrastructure/` - Contains Terraform files with intentional security issues for Checkov demo
- `src/` - Contains Lambda function code
- `.github/workflows/` - Contains GitHub Actions workflow for running both linters

## Intentional Security Issues

### Terraform/Checkov Issues
1. Database (RDS Aurora):
   - Missing encryption at rest
   - Missing Multi-AZ
   - Missing monitoring features
   - Insecure password handling

2. Load Balancer:
   - HTTP instead of HTTPS
   - Missing access logging
   - Missing WAF
   - Missing deletion protection

3. Lambda:
   - No VPC config
   - No observability features
   - Missing security features

4. ECR:
   - Missing security scanning
   - Basic encryption
   - Mutable tags

### Docker/Hadolint Issues
- Deprecated MAINTAINER instruction
- Multiple RUN commands
- Root user
- Latest tag usage

## Common Tasks
When working in this repo:
1. Maintain the intentional security issues for demo purposes
2. Keep issues well-documented in code comments
3. Ensure GitHub Actions workflow runs both tools in parallel
4. Keep Lambda function simple (Hello World)