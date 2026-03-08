# 🛡️ Cloud Aegis

Built a system on my personal AWS account that detects exposed resources in real time, blocks them automatically, and emails me to approve or restore. No frontend. No framework. Just AWS wired together the right way.

The moment an S3 bucket goes public, an EC2 launches with a public IP, or an RDS instance becomes accessible — CloudTrail picks it up, EventBridge fires, Step Functions runs the pipeline, the exposure gets blocked, and I get an HTML email with two buttons. By the time I read it, it's already fixed.

13 services. 4 Lambda functions. 5 EventBridge rules watching the entire account in real time. 4 IAM roles with zero managed policies. ~900 lines of Python. No dashboard. No third-party tools. Just AWS doing what it's supposed to do.

---

## How It Works

```
CloudTrail → EventBridge (5 rules) → Step Functions (aegis-workflow)
                                              ↓
                                      aegis-analyzer        detects + deduplicates
                                              ↓
                                      aegis-scorer          assigns risk level
                                              ↓
                                      aegis-remediator      blocks + alerts
                                        ↙   ↓   ↘   ↘
                                    S3  DynamoDB  SES  Security Hub
                                              ↓
                                      API Gateway → aegis-approval
```

---

## What Gets Detected

| Resource | Trigger |
|---|---|
| S3 bucket | Made public via bucket policy, ACL, or public access block removed |
| EC2 instance | Launched with a public IP |
| RDS instance | Created or modified with PubliclyAccessible: true |
| Load balancer | Created with internet-facing scheme |
| Lambda function URL | Created or updated |

---

## Services Used

CloudTrail · EventBridge · Step Functions · Lambda (×4) · DynamoDB · SNS · SES · API Gateway · S3 · Secrets Manager · CloudWatch · AWS Config · Security Hub

---

## Repository Structure

```
cloud-aegis/
├── README.md
├── lambda/
│   └── lambda-code.md        ← all 4 function codes
├── iam/
│   └── iam-roles.md          ← all 4 IAM role policies
├── eventbridge/
│   └── eventbridge-rules.md  ← all 5 event patterns
├── stepfunctions/
│   └── step-functions.md     ← ASL definition + setup
├── apigateway/
│   └── api-gateway.md        ← endpoints + setup
├── cloudwatch/
│   └── cloudwatch-alarms.md  ← all 4 alarms
├── config/
│   └── config-rules.md       ← all 5 managed rules + CloudShell setup
├── dynamodb/
│   └── dynamodb-schema.md    ← table schema + 4 GSIs
└── screenshots/
    └── screenshots.md
```

---

## Build Guide

Everything in the **AWS Console** unless noted. Follow in order — each phase depends on what came before it.

Region for everything: **us-east-1**

---

<details>
<summary><b>Phase 0 — Before You Start</b></summary>

- AWS account (Free Tier works)
- A verified email address for SES
- Browser open at console.aws.amazon.com
- Keep a notepad open — save every ARN as you create it
- Set region to us-east-1 on every service page

</details>

---

<details>
<summary><b>Phase 1 — IAM Roles</b></summary>

Create 4 roles. All least-privilege — exact actions only, no AWS managed policies attached.

Full policies → [iam/iam-roles.md](./iam/iam-roles.md)

**For each role:**

1. IAM → Roles → **Create role**
2. Trusted entity: AWS service → **Lambda** (use **Step Functions** for AegisStepFunctionsRole)
3. Skip permissions — click through to the end
4. Name the role → **Create role**
5. Open the role → **Add permissions → Create inline policy → JSON tab**
6. Paste the matching policy from iam/iam-roles.md
7. Policy name: same as the role → **Create policy**

| Role | Used By |
|---|---|
| AegisAnalyzerRole | aegis-analyzer + aegis-scorer |
| AegisRemediatorRole | aegis-remediator |
| AegisApprovalRole | aegis-approval |
| AegisStepFunctionsRole | Step Functions state machine |

> If Step Functions throws a CloudWatch logging error later — use Create new role in the Step Functions console instead. Then manually add a Lambda invoke policy to that auto-created role.

</details>

---

<details>
<summary><b>Phase 2 — DynamoDB Table</b></summary>

Full schema → [dynamodb/dynamodb-schema.md](./dynamodb/dynamodb-schema.md)

1. DynamoDB → Tables → **Create table**
2. Table name: `aegis-findings`
3. Partition key: `finding_id` (String)
4. Table settings: Customize → Capacity mode: **On-demand**
5. **Create table**

**Add 4 GSIs** — Table → Indexes tab → Create index, repeat 4 times:

| Index Name | Partition Key |
|---|---|
| status-index | status (String) |
| exposure-type-index | exposure_type (String) |
| resource-index | resource_id (String) |
| risk-index | risk_level (String) |

</details>

---

<details>
<summary><b>Phase 3 — S3 Buckets</b></summary>

**Reports bucket:**
1. S3 → **Create bucket** → name: `aegis-reports-YOURNAME`
2. Block all public access: ON → Create → copy ARN

**Trail logs bucket** (or let CloudTrail create it in Phase 4):
- Name: `aegis-trail-logs-YOURNAME` — same settings

</details>

---

<details>
<summary><b>Phase 4 — CloudTrail</b></summary>

1. CloudTrail → **Create trail**
2. Trail name: `aegis-trail`
3. S3 bucket: create new → `aegis-trail-logs-YOURNAME`
4. CloudWatch Logs: **Enable** → Log group: `/aws/cloudtrail/aegis` → New IAM role: `AegisCWRole`
5. Events: Management events → **Write** only
6. **Create trail**

CloudTrail takes a few minutes to start delivering events. API calls made before this step won't appear.

</details>

---

<details>
<summary><b>Phase 5 — SNS Topic</b></summary>

1. SNS → Topics → **Create topic** → Standard → name: `aegis-alerts` → Create → copy ARN
2. Topic → **Create subscription** → Protocol: Email → your email → Create
3. Confirm the subscription link in your inbox

</details>

---

<details>
<summary><b>Phase 6 — SES Email Verification</b></summary>

1. SES → Verified identities → **Create identity** → Email address → your email
2. Confirm the verification link in your inbox
3. Status must show **Verified** before moving on

> SES sandbox: sender and recipient must be the same verified email. Both go into Secrets Manager next.

</details>

---

<details>
<summary><b>Phase 7 — Secrets Manager</b></summary>

1. Secrets Manager → **Store a new secret** → Other type of secret
2. Add 4 key-value pairs:

| Key | Value |
|---|---|
| sender_email | your verified SES email |
| recipient_email | your verified SES email |
| approval_token_secret | any random string (32+ chars) |
| slack_webhook_url | your Slack incoming webhook URL |

3. Secret name: `aegis/email-config` → Store → copy ARN

</details>

---

<details>
<summary><b>Phase 8 — Lambda Functions</b></summary>

Create 4 functions. All Python 3.12.

Full code for all 4 → [lambda/lambda-code.md](./lambda/lambda-code.md)

**For each function:**
1. Lambda → **Create function** → Author from scratch
2. Runtime: Python 3.12 | Architecture: x86_64
3. Execution role: Use existing role (see table)
4. **Create function** → Code tab → delete everything → paste code from lambda-code.md
5. Update any `# CONFIGURE:` lines in the code
6. Configuration → General → set timeout → **Deploy**

| Function | Role | Timeout |
|---|---|---|
| aegis-analyzer | AegisAnalyzerRole | 1 min |
| aegis-scorer | AegisAnalyzerRole | 30 sec |
| aegis-remediator | AegisRemediatorRole | 2 min |
| aegis-approval | AegisApprovalRole | 30 sec |

> Leave API_GATEWAY_URL in aegis-remediator as a placeholder — fill it after Phase 10.

</details>

---

<details>
<summary><b>Phase 9 — EventBridge Rules</b></summary>

Create 5 rules. All target aegis-workflow.

Full patterns → [eventbridge/eventbridge-rules.md](./eventbridge/eventbridge-rules.md)

**For each rule:**
1. EventBridge → Rules → **Create rule**
2. Name (see table) | Event bus: **default** | Rule type: Rule with an event pattern → Next
3. Scroll down → **Custom pattern (JSON editor)** → paste the pattern
4. Next → Target: AWS service → Step Functions state machine → **aegis-workflow**
5. Execution role: Create new role → **Create rule**

> The Event source toggle may switch to "Other" when you select custom pattern — ignore it.

| Rule | Watches |
|---|---|
| aegis-s3-exposure | S3 public access changes |
| aegis-ec2-exposure | EC2 launched with public IP |
| aegis-rds-exposure | RDS made publicly accessible |
| aegis-alb-exposure | Internet-facing load balancer created |
| aegis-lambda-url-exposure | Lambda function URL created or updated |

</details>

---

<details>
<summary><b>Phase 10 — API Gateway</b></summary>

Full setup → [apigateway/api-gateway.md](./apigateway/api-gateway.md)

1. API Gateway → **Create API → REST API → Build**
2. Name: `aegis-approval-api` | Endpoint: Regional → Create

**Create /approve:**
Resources → Create resource → `approve` → Create → Create method → GET → Lambda proxy ON → aegis-approval → Create method

**Create /restore:**
Root / → Create resource → `restore` → same steps → aegis-approval

**Deploy:**
Deploy API → New stage → `prod` → Deploy → copy the Invoke URL

**Update aegis-remediator:**
Lambda → aegis-remediator → Code tab → replace API_GATEWAY_URL with your Invoke URL → Deploy

</details>

---

<details>
<summary><b>Phase 11 — Step Functions</b></summary>

Full setup + ASL → [stepfunctions/step-functions.md](./stepfunctions/step-functions.md)

**Step 1 — Create log group:**

1. CloudWatch → Log groups → **Create log group**
2. Name: `/aws/states/aegis-workflow` | Retention: 90 days → Create → copy ARN

Run this in **CloudShell** (Step Functions can't write to CloudWatch without it):

```bash
aws logs put-resource-policy \
  --policy-name AegisStepFunctionsLogPolicy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":["logs:CreateLogDelivery","logs:GetLogDelivery","logs:UpdateLogDelivery","logs:DeleteLogDelivery","logs:ListLogDeliveries","logs:PutLogEvents","logs:PutResourcePolicy","logs:DescribeResourcePolicies","logs:DescribeLogGroups"],"Resource":"*"}]}'
```

**Step 2 — Create state machine:**

1. Step Functions → **Create state machine** → Write your workflow in code → Standard
2. Delete everything → paste ASL from stepfunctions/step-functions.md
3. Next → Name: `aegis-workflow`
4. Permissions: Choose existing role → **AegisStepFunctionsRole**
5. Logging: Level **ALL** → paste Log Group ARN → Include execution data: ✅
6. **Create state machine** → copy ARN

> CloudWatch error during creation → use Create new role instead, then manually add Lambda invoke policy to that role.

</details>

---

<details>
<summary><b>Phase 12 — CloudWatch Alarms</b></summary>

Full config → [cloudwatch/cloudwatch-alarms.md](./cloudwatch/cloudwatch-alarms.md)

4 alarms — 3 Lambda error alarms + 1 Step Functions failure alarm. All notify aegis-alerts.

CloudWatch → Alarms → Create alarm → Select metric → set each one per cloudwatch-alarms.md → Statistic: Sum | Period: 5 min | Threshold: Greater than 0 → Notification: aegis-alerts → Create alarm

</details>

---

<details>
<summary><b>Phase 13 — AWS Config</b></summary>

Full setup + CloudShell commands → [config/config-rules.md](./config/config-rules.md)

5 managed rules. Periodic safety net — catches anything EventBridge missed.

Enable Config first (console or CloudShell if the console wizard fails), then add the 5 rules. Full commands in config-rules.md.

</details>

---

<details>
<summary><b>Phase 14 — Security Hub</b></summary>

1. Security Hub → **Enable Security Hub**
2. Enable: **AWS Foundational Security Best Practices** + **CIS AWS Foundations**
3. After a full test, findings from aegis-remediator will appear here automatically in ASFF format

</details>

---

<details>
<summary><b>Phase 15 — End-to-End Test</b></summary>

Open two tabs — Step Functions executions + S3.

**Trigger a detection:**

1. S3 → Create bucket → `aegis-test-YOURNAME` → uncheck Block Public Access → Create
2. Open bucket → Permissions → Bucket policy → paste:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicRead",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::aegis-test-YOURNAME/*"
  }]
}
```

Wait 3–10 minutes (CloudTrail propagation delay is normal).

**What should happen:**
- New execution in Step Functions → Status: **Succeeded**
- Graph view → full green pipeline
- HTML alert email with two action buttons
- S3 bucket → Block Public Access back **ON**
- DynamoDB → new finding row
- Security Hub → new finding

</details>

---

<details>
<summary><b>Troubleshooting</b></summary>

**No execution after 15 minutes** — CloudTrail Active? EventBridge rule Enabled? State machine ARN correct in the rule target?

**Execution → NoExposureDetected** — Not a failure. Duplicate event or analyzer couldn't confirm exposure. Working as designed.

**Email not arriving** — SES Verified? Check spam. Both sender and recipient in Secrets Manager must be the same verified email.

**Step Functions CloudWatch error** — Run the CloudShell command in Phase 11. Or use Create new role during state machine creation.

**Config recorder failed** — Use the CloudShell method in config-rules.md.

**403 on approve/restore button** — API_GATEWAY_URL in aegis-remediator doesn't match your prod stage URL. Or approval_token_secret changed after findings were stored.

</details>

---

## Author

Made by **Ridam Darji** — [LinkedIn](https://www.linkedin.com/in/ridamdarji/) · **w1tn3sss**
