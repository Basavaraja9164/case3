resource "aws_s3_bucket" "s3_bucket_billing" {
  bucket = "s3_bucket_billing"

}

resource "aws_s3_bucket" "s3_bucket_cloudtrail_event_detection" {
  bucket = "s3_bucket_account_logs_insights"

}


resource "aws_s3_bucket_policy" "s3_access_policy" {
  bucket = aws_s3_bucket.s3_bucket_billing.id

  policy = <<EOF

  {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": ["arn:aws:s3:::<bucket_name>/*"]
        }
    ]
}

EOF
}

