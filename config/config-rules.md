# AWS Config — Compliance Rules

5 managed rules running continuous compliance checks. Catches anything EventBridge missed — acts as the periodic safety net.

---

## How to Enable AWS Config (AWS Console)

1. AWS Config → Get started
2. Recording strategy: All resource types | Frequency: Continuous
3. S3 bucket: choose `aegis-reports-YOURNAME`
4. SNS topic: `aegis-alerts`
5. IAM role: Create AWS Config service-linked role
6. Confirm

> If you get "Configuration recorder creation failed", use the CloudShell method below.

**CloudShell method (more reliable):**

```bash
# Add S3 permissions for Config
aws s3api put-bucket-policy \
  --bucket YOUR_REPORTS_BUCKET \
  --policy '{"Version":"2012-10-17","Statement":[{"Sid":"AWSConfigBucketPermissionsCheck","Effect":"Allow","Principal":{"Service":"config.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::YOUR_REPORTS_BUCKET"},{"Sid":"AWSConfigBucketDelivery","Effect":"Allow","Principal":{"Service":"config.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::YOUR_REPORTS_BUCKET/AWSLogs/YOUR_ACCOUNT_ID/Config/*","Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}}]}'

# Create recorder
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::YOUR_ACCOUNT_ID:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig \
  --recording-group allSupported=true,includeGlobalResourceTypes=false

# Create delivery channel
aws configservice put-delivery-channel \
  --delivery-channel name=default,s3BucketName=YOUR_REPORTS_BUCKET,snsTopicARN=arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:aegis-alerts

# Start recording
aws configservice start-configuration-recorder --configuration-recorder-name default

# Verify — should show "recording": true
aws configservice describe-configuration-recorder-status
```

---

## Add the 5 Rules

**Console:** Config → Rules → Add rule → search each name below → Next → Save

**CloudShell (faster):**

```bash
aws configservice put-config-rule --config-rule '{"ConfigRuleName":"s3-bucket-public-read-prohibited","Source":{"Owner":"AWS","SourceIdentifier":"S3_BUCKET_PUBLIC_READ_PROHIBITED"}}'
aws configservice put-config-rule --config-rule '{"ConfigRuleName":"s3-bucket-public-write-prohibited","Source":{"Owner":"AWS","SourceIdentifier":"S3_BUCKET_PUBLIC_WRITE_PROHIBITED"}}'
aws configservice put-config-rule --config-rule '{"ConfigRuleName":"rds-instance-public-access-check","Source":{"Owner":"AWS","SourceIdentifier":"RDS_INSTANCE_PUBLIC_ACCESS_CHECK"}}'
aws configservice put-config-rule --config-rule '{"ConfigRuleName":"restricted-ssh","Source":{"Owner":"AWS","SourceIdentifier":"INCOMING_SSH_DISABLED"}}'
aws configservice put-config-rule --config-rule '{"ConfigRuleName":"restricted-common-ports","Source":{"Owner":"AWS","SourceIdentifier":"RESTRICTED_INCOMING_TRAFFIC"}}'

# Verify all 5
aws configservice describe-config-rules --query 'ConfigRules[].ConfigRuleName'
```

---

## Rules Reference

| Rule | What It Checks |
|---|---|
| `s3-bucket-public-read-prohibited` | S3 buckets with public read access |
| `s3-bucket-public-write-prohibited` | S3 buckets with public write access |
| `rds-instance-public-access-check` | RDS with `PubliclyAccessible=true` |
| `restricted-ssh` | Security groups with SSH open to `0.0.0.0/0` |
| `restricted-common-ports` | Security groups with unrestricted common ports |
