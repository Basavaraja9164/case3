provider "aws" {
  region     = "us-east-2"
}
resource "aws_vpc" "vpc_acct_A" {
  cidr_block           = "10.0.0.0/27"
  enable_dns_hostnames = "true"
  enable_dns_support   = "true"
  instance_tenancy     = "default"

  tags = {
    Name = "vpc_acct_A"
  }
}

resource "aws_subnet" "subnets_acct_A" {
  vpc_id            = aws_vpc.vpc_acct_A.id
  cidr_block        = "10.0.1.0/28"
  availability_zone = var.availability_zones
  tags = {
    Name = "pt-subnet-name"
  }
}

resource "aws_internet_gateway" "igw_acct_A" {
  vpc_id = aws_vpc.vpc_acct_A.id

  tags = {
    Name = "internet_gateway_acct_A"
  }
}

resource "aws_route_table" "private-rt_acct_A" {
  vpc_id = aws_vpc.vpc_acct_A.id
  tags = {
    Name = "private_route_table"
  }
}


resource "aws_route_table_association" "subnet-assoc" {
  route_table_id = aws_route_table.private-rt_acct_A.id
  subnet_id      = aws_subnet.subnets_acct_A.id

}

resource "aws_security_group" "sg_acct_A" {
  vpc_id = aws_vpc.vpc_acct_A.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "My_security_group"
  }
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "cloudtrail_kms" {
  statement {
    actions = [
      "kms:*",
    ]
    principals {
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
      ]
      type = "AWS"
    }
    resources = [
      "*",
    ]
    sid = "Enable IAM User Permissions"
  }

  statement {
    actions = [
      "kms:GenerateDataKey*",
    ]
    condition {
      test = "StringLike"
      values = [
        "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*",
      ]
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
    }
    principals {
      identifiers = [
        "cloudtrail.amazonaws.com",
      ]
      type = "Service"
    }
    resources = [
      "*",
    ]
    sid = "Allow CloudTrail to encrypt logs"
  }

  statement {
    actions = [
      "kms:DescribeKey",
    ]
    principals {
      identifiers = [
        "cloudtrail.amazonaws.com",
      ]
      type = "Service"
    }
    resources = [
      "*",
    ]
    sid = "Allow CloudTrail to describe key"
  }
}

resource "aws_kms_key" "guardduty_logging_key" {
  description         = "cloudtrail log key for events for unusual activity"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.cloudtrail_kms.json
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/mykmskey"
  target_key_id = aws_kms_key.guardduty_logging_key.key_id
}
853062406383
locals {
  KeyPair = "private-key"
}

resource "aws_iam_instance_profile" "demo-profile" {
  name = "demo_profile"
  role = aws_iam_role.iam_role_cross_account_A.name
}

resource "tls_private_key" "private" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "generated_key" {
  key_name = local.KeyPair
  #public_key = file("~/.ssh/private-key.pub")
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCs+NZZFh9i2mnP+0n0+uVE/7mRyEoYLsV/SLTCnvcnj8BrTBnftzaD5/JhNV+d2lv6PMbYQfKJvvzLqMhVrBohsMnd2iY/Pz+mCIbOGOrMD5McOX3PXuIbffBKOy7hCJFbmmjFMXy7PF6biy1MIiP3yjAUcWv7aOg1/5JzL8GTmQHDnx42Qgt0Y07T71oXioUkv1Aix9YH6wWZElwQXa38+zoZUb8JnaZmlSNyWlUpeNFJ1g977RyeSylahLaTPsHoxDZ/QGrvoKQVtJ5SSDPuK8PhdRlgTJB4Q+LDAewAW6+mQbK8pbQ9xSJh7J5oTSFfgGzHpuPdUE70DJT6t9USq2S+mHAGvN1jDbfhyWX/gg0sIpAhwrM015QgGdc1SpCJrZ5GCwPQ7TQluVnAXeWGl3U4LCdjWHXLJY1fiYRRBIg2Be3tI8ooiHoZDnwwU9ek51QLhTxt8foLFcjNsLGi8YG4mI6lAaPg32rQKeouU5/EUpalaMa0ioIrTJ1ANks= MUMBAI1+SaiS2@CTAADPG02X1Z2"
}

resource "aws_instance" "instances" {
  ami                    = "ami-089313d40efd067a9" # Replace with your desired AMI ID
  instance_type          = "t2.small"
  subnet_id              = aws_subnet.subnets_acct_A.id
  vpc_security_group_ids = [aws_security_group.sg_acct_A.id]
  iam_instance_profile   = aws_iam_instance_profile.demo-profile.name
  key_name               = aws_key_pair.generated_key.key_name

  # connection {
  #   type        = "ssh"
  #   user        = "ec2-user"
  #   private_key = file(aws_key_pair.generated_key)
  #   host        = self.private_ip
  # }

  tags = {
    Name = "instance-1"
  }


  user_data = <<-EOF
    
  sudo yum upgrade -y
  sudo yum update -y
  sudo ssh-keygen -y
  sudo yum install -y awslogs

  #to modify the default location name and set it to current location
  sed -i "s/us-east-1/us-west-2/g" /etc/awslogs/awscli.conf

  #start the aws logs agent
  sudo systemctl start awslogsd

  #start the service at each system boot.
  sudo systemctl enable awslogsd.service

  echo -e "#!/bin/bash\#this script is for access the s3 buckets present in the appropriate account\aws s3 ec2-access-logging-bucket-112233 ls >> /home/ec2-user/userdata.sh
  sudo ./home/ec2-user/userdata.sh
  EOF
}
resource "aws_cloudtrail" "my-demo-cloudtrail" {
  name                          = "my-demo-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.s3_bucket_cloudtrail_event_detection.id
  enable_logging                = true
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.guardduty_logging_key.arn
  depends_on                    = [aws_s3_bucket_policy.s3_access_policy, aws_s3_bucket.s3_bucket_cloudtrail_event_detection, aws_kms_key.guardduty_logging_key]
}

resource "aws_iam_role" "iam_role_cross_account_A" {
  name = "role_for_account_B"

  assume_role_policy = <<EOF

  {
    "__comment__": "Need to update with ARN of the role created in account B near resource",
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "role arn created in account B"
    }]
}

EOF
}


resource "aws_iam_role" "iam_role_account_B" {
  name = "role_for_account_B"

  assume_role_policy = <<EOF

  {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::*"]
        }
    ]
}

EOF
}
