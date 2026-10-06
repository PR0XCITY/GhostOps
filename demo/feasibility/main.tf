# Phase 0 feasibility check: deliberately risky resources applied to MiniStack.
# Fake credentials only. Every endpoint points at the local emulator.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "ministack_endpoint" {
  type    = string
  default = "http://localhost:4566"
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    ec2 = var.ministack_endpoint
    iam = var.ministack_endpoint
    s3  = var.ministack_endpoint
    sts = var.ministack_endpoint
  }
}

# RISK: SSH open to the whole internet.
resource "aws_security_group" "ssh_open" {
  name        = "ghostops-feasibility-ssh-open"
  description = "Feasibility: SSH open to the world"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RISK: full admin, every action on every resource.
resource "aws_iam_policy" "admin_star" {
  name        = "ghostops-feasibility-admin-star"
  description = "Feasibility: Action * on Resource *"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_s3_bucket" "data" {
  bucket = "ghostops-feasibility-bucket"
}

output "security_group_id" {
  value = aws_security_group.ssh_open.id
}

output "iam_policy_arn" {
  value = aws_iam_policy.admin_star.arn
}

output "s3_bucket" {
  value = aws_s3_bucket.data.bucket
}
