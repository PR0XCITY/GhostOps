# "Bad" demo: three classic misconfigurations GhostOps must block.
#   1. Security group with SSH (22) open to 0.0.0.0/0
#   2. IAM policy allowing Action * on Resource *
#   3. S3 bucket made public-read (ACL + public access block disabled)
#   4. RDS instance without storage encryption
# plus an EC2 instance behind the open security group (its blast radius).
# Provider points at MiniStack with fake credentials. Never real AWS.

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
    rds = var.ministack_endpoint
    s3  = var.ministack_endpoint
    sts = var.ministack_endpoint
  }
}

resource "aws_security_group" "ssh_open" {
  name        = "ghostops-bad-ssh-open"
  description = "SSH open to the world"

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

# Attached to the open security group, so SSH to it is reachable from anywhere.
resource "aws_instance" "web" {
  ami                    = "ami-12345678"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.ssh_open.id]

  tags = {
    Name = "ghostops-bad-web"
  }
}

resource "aws_iam_policy" "admin_star" {
  name        = "ghostops-bad-admin-star"
  description = "Full admin: Action * on Resource *"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_s3_bucket" "public" {
  bucket = "ghostops-bad-public-bucket"
}

# ACLs only take effect when object ownership allows them.
resource "aws_s3_bucket_ownership_controls" "public" {
  bucket = aws_s3_bucket.public.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Every public-access guard switched off.
resource "aws_s3_bucket_public_access_block" "public" {
  bucket                  = aws_s3_bucket.public.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "public" {
  bucket = aws_s3_bucket.public.id
  acl    = "public-read"

  depends_on = [
    aws_s3_bucket_ownership_controls.public,
    aws_s3_bucket_public_access_block.public,
  ]
}

resource "aws_db_instance" "unencrypted" {
  identifier          = "ghostops-bad-unencrypted-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "ghostops"
  storage_encrypted   = false
  skip_final_snapshot = true

  # Password lives in Secrets Manager, so none appears in config or plan JSON.
  manage_master_user_password = true
}
