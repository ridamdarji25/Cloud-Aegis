# IAM — Roles & Policies

4 roles. All least-privilege — exact actions only, zero AWS managed policies.

For each role: **IAM → Roles → Create role → AWS service → Lambda** (Step Functions for the last one) → skip permissions → create → open role → **Add permissions → Create inline policy → JSON** → paste → create policy.

---

## AegisAnalyzerRole

Used by `aegis-analyzer` and `aegis-scorer`. Needs read access to EC2, S3, RDS to inspect resources and DynamoDB write access to store findings.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2ReadForAnalysis",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeAddresses"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3ReadForAnalysis",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock"
      ],
      "Resource": "*"
    },
    {
      "Sid": "RDSReadForAnalysis",
      "Effect": "Allow",
      "Action": ["rds:DescribeDBInstances"],
      "Resource": "*"
    },
    {
      "Sid": "DynamoWrite",
      "Effect": "Allow",
      "Action": ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Query"],
      "Resource": "arn:aws:dynamodb:us-east-1:*:table/aegis-findings*"
    },
    {
      "Sid": "S3ReportWrite",
      "Effect": "Allow",
      "Action": ["s3:PutObject"],
      "Resource": "arn:aws:s3:::aegis-reports-*/*"
    },
    {
      "Sid": "Logging",
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
```

---

## AegisRemediatorRole

Used by `aegis-remediator`. Needs write access to block exposures across S3, EC2, RDS — plus SES, SNS, Security Hub, Secrets Manager, S3 reports.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2Remediate",
      "Effect": "Allow",
      "Action": [
        "ec2:RevokeSecurityGroupIngress",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3Remediate",
      "Effect": "Allow",
      "Action": ["s3:PutBucketPublicAccessBlock","s3:GetBucketPublicAccessBlock"],
      "Resource": "*"
    },
    {
      "Sid": "RDSRemediate",
      "Effect": "Allow",
      "Action": ["rds:ModifyDBInstance","rds:DescribeDBInstances"],
      "Resource": "*"
    },
    {
      "Sid": "Alerting",
      "Effect": "Allow",
      "Action": ["sns:Publish","ses:SendEmail"],
      "Resource": "*"
    },
    {
      "Sid": "DynamoWrite",
      "Effect": "Allow",
      "Action": ["dynamodb:PutItem","dynamodb:GetItem","dynamodb:UpdateItem","dynamodb:Query"],
      "Resource": "arn:aws:dynamodb:us-east-1:*:table/aegis-findings*"
    },
    {
      "Sid": "SecretsRead",
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:us-east-1:*:secret:aegis/*"
    },
    {
      "Sid": "SecurityHubWrite",
      "Effect": "Allow",
      "Action": ["securityhub:BatchImportFindings"],
      "Resource": "*"
    },
    {
      "Sid": "Logging",
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
```

---

## AegisApprovalRole

Used by `aegis-approval`. Needs DynamoDB read/write to update finding status, SES to send confirmation, S3 to restore access, Secrets Manager to verify the HMAC token.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DynamoReadWrite",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem","dynamodb:UpdateItem"],
      "Resource": "arn:aws:dynamodb:us-east-1:*:table/aegis-findings*"
    },
    {
      "Sid": "EC2Restore",
      "Effect": "Allow",
      "Action": ["ec2:AuthorizeSecurityGroupIngress","ec2:DescribeSecurityGroups"],
      "Resource": "*"
    },
    {
      "Sid": "S3Restore",
      "Effect": "Allow",
      "Action": ["s3:PutBucketPublicAccessBlock","s3:GetBucketPublicAccessBlock"],
      "Resource": "*"
    },
    {
      "Sid": "RDSRestore",
      "Effect": "Allow",
      "Action": ["rds:ModifyDBInstance"],
      "Resource": "*"
    },
    {
      "Sid": "EmailAndSecrets",
      "Effect": "Allow",
      "Action": ["ses:SendEmail","secretsmanager:GetSecretValue"],
      "Resource": "*"
    },
    {
      "Sid": "Logging",
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
```

---

## AegisStepFunctionsRole

Used by Step Functions state machine `aegis-workflow`. Only needs to invoke the 4 aegis Lambda functions.

Trusted entity: **AWS service → Step Functions** (not Lambda)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["lambda:InvokeFunction"],
      "Resource": [
        "arn:aws:lambda:us-east-1:*:function:aegis-*"
      ]
    }
```
