# "Good" demo: low-risk change GhostOps should auto-approve.
#   - S3 bucket with ownership/cost tags
#   - CloudWatch alarm on the bucket's size
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

# Only the bucket uses this, so changing it yields an in-place update of the
# bucket while the alarm stays unchanged (used for the update/no-op fixture).
variable "environment" {
  type    = string
  default = "dev"
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
    cloudwatch = var.ministack_endpoint
    s3         = var.ministack_endpoint
    sts        = var.ministack_endpoint
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "ghostops-good-logs-bucket"

  tags = {
    Project     = "ghostops"
    Environment = var.environment
    Owner       = "platform-team"
    CostCenter  = "cloud-arch-101"
  }
}

resource "aws_cloudwatch_metric_alarm" "bucket_size" {
  alarm_name          = "ghostops-good-logs-bucket-size"
  alarm_description   = "Logs bucket larger than 5 GB"
  namespace           = "AWS/S3"
  metric_name         = "BucketSizeBytes"
  statistic           = "Average"
  period              = 86400
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 5368709120
  treat_missing_data  = "notBreaching"

  dimensions = {
    BucketName  = aws_s3_bucket.logs.bucket
    StorageType = "StandardStorage"
  }

  tags = {
    Project = "ghostops"
    Owner   = "platform-team"
  }
}
