# 🛡️ Cloud Aegis

![AWS](https://img.shields.io/badge/AWS-Serverless-orange)
![Python](https://img.shields.io/badge/Python-3.12-blue)
![Cloud Security](https://img.shields.io/badge/Domain-Cloud%20Security-red)
![License](https://img.shields.io/badge/License-MIT-green)

Built this on my personal AWS account as a hands-on cloud security implementation. The idea was simple — wire AWS services together so that the moment something in my account becomes publicly exposed, it gets detected, blocked automatically, and I get an email to approve or restore it. No frontend, no third-party tools, no frameworks. Just AWS doing what it's built to do.

The exposure is usually blocked before I even finish reading the alert.

**By the numbers**

* 13 AWS services
* 4 Lambda functions
* 5 EventBridge rules watching the entire account
* 4 IAM roles — zero managed policies, exact actions only
* ~900 lines of Python
* Built and tested entirely in the AWS Console

---

## 🗺️ Architecture Diagram

> Coming soon — will be attached here.

---

## ⚡ How It Works

Every step runs automatically. Here's exactly what happens the moment a resource gets exposed:

**Step 1 — CloudTrail catches the API call**
Every action in an AWS account — creating a bucket, launching an EC2, modifying an RDS — is an API call. CloudTrail records all of them in real time. This is the starting point. Without CloudTrail, nothing else triggers.

**Step 2 — EventBridge matches the event**
5 EventBridge rules sit watching the CloudTrail stream. Each rule looks for a specific pattern — an S3 bucket policy being added, an EC2 launched with `associatePublicIpAddress: true`, an RDS with `publiclyAccessible: true`, an internet-facing ALB, or a Lambda URL being created. The moment a matching event arrives, EventBridge immediately triggers the Step Functions state machine.

**Step 3 — Step Functions orchestrates the pipeline**
`aegis-workflow` is the brain of the operation. It doesn't detect or remediate anything itself — it calls each Lambda function in sequence, handles retries with exponential backoff if something fails, and routes the execution based on what each function returns.

**Step 4 — aegis-analyzer identifies the exposure**
Reads the raw CloudTrail event and extracts what matters — resource type, ARN, account, region, exposure type. Also queries DynamoDB to check if this resource is already being handled. If it's a duplicate, the workflow ends cleanly at `NoExposureDetected`. Not a failure — deduplication working as designed.

**Step 5 — aegis-scorer assigns a risk level**
Takes the finding and scores it — CRITICAL, HIGH, MEDIUM, or LOW — based on exposure type and severity. A public S3 bucket with a wildcard policy is CRITICAL. A Lambda URL is MEDIUM. Score gets written to DynamoDB with full finding context.

**Step 6 — aegis-remediator blocks it and alerts**
The actual fix. Turns Block Public Access back on for S3, removes the offending security group rule for EC2, sets RDS back to private. Once blocked, sends an HTML email via SES with two HMAC-signed buttons. Also pushes the finding to Security Hub in ASFF format and notifies Slack via SNS.

**Step 7 — Approve or restore from the email**
The email buttons hit API Gateway → `aegis-approval`. First verifies the HMAC-SHA256 token — tamper with the link and you get 403. If valid, updates finding status in DynamoDB and sends a confirmation email. Restore reverses the remediation.

```
CloudTrail → EventBridge (5 rules) → Step Functions (aegis-workflow)
                                              ↓
                                      aegis-analyzer     ← detects + deduplicates
                                              ↓
                                      aegis-scorer       ← CRITICAL / HIGH / MEDIUM / LOW
                                              ↓
                                      aegis-remediator   ← blocks + alerts
                                       ↙    ↓    ↘    ↘
                                      S3   DDB   SES  Security Hub
                                              ↓
                                      API Gateway → aegis-approval  ← approve or restore
```

---

## 🔍 What Gets Detected

| Resource | Trigger |
|---|---|
| S3 bucket | Made public via bucket policy, ACL, or public access block removed |
| EC2 instance | Launched with a public IP |
| RDS instance | Created or modified with PubliclyAccessible: true |
| Load balancer | Created with internet-facing scheme |
| Lambda function URL | Created or updated |

---

## 🛠️ AWS Services Used

| Service | Role |
|---|---|
| CloudTrail | Records every Write API call across the account |
| EventBridge | 5 rules — matches specific exposure patterns and fires instantly |
| Step Functions | Orchestrates the full detection → scoring → remediation pipeline |
| Lambda | 4 functions — analyzer, scorer, remediator, approval handler |
| DynamoDB | Stores all findings with 4 GSIs for querying |
| SNS | Routes Slack notifications and CloudWatch alarm alerts |
| SES | Sends the HTML alert email with approve / restore buttons |
| API Gateway | /approve and /restore endpoints for the email buttons |
| S3 | Stores reports and CloudTrail logs |
| Secrets Manager | Holds email config, Slack webhook, HMAC token secret |
| CloudWatch | Alarms on Lambda errors and Step Functions failures |
| AWS Config | 5 managed compliance rules — periodic safety net |
| Security Hub | Centralized findings in ASFF format |

---

## 📁 Repository Structure

```
📦 cloud-aegis/
├── README.md
├── lambda/
│   └── lambda-code.md           ← all 4 function codes
├── iam/
│   └── iam-roles.md             ← all 4 IAM role policies
├── eventbridge/
│   └── eventbridge-rules.md     ← all 5 event patterns
├── stepfunctions/
│   └── step-functions.md        ← ASL definition + setup
├── apigateway/
│   └── api-gateway.md           ← endpoints + setup
├── cloudwatch/
│   └── cloudwatch-alarms.md     ← all 4 alarms
├── config/
│   └── config-rules.md          ← all 5 managed rules + CloudShell setup
├── dynamodb/
│   └── dynamodb-schema.md       ← table schema + 4 GSIs
└── screenshots/
    └── screenshots.md
```

---

## 🔧 Build Guide

Everything configured directly in the **AWS Console** unless noted. Follow phases in order — each one depends on what came before.

Region for everything:
```
us-east-1
```

---

<details>
<summary><b>Phase 0 — Before You Start</b></summary>

<br>

### Prerequisites

Before touching anything in the console, have these ready:

* **AWS account** — Free Tier is enough to build and test this entire project
* **Verified email** — needed for SES in Phase 6, have inbox access ready
* **Browser at** https://console.aws.amazon.com
* **Notepad** — you'll generate a lot of ARNs across 15 phases. Save every single one as you go. Hunting for them mid-build wastes time
* **Region** — set to `us-east-1` on every service page before doing anything. All resources must be in the same region

### Cost Note

Lambda, DynamoDB, CloudWatch, SNS, SES, Step Functions all have Free Tier limits that are more than enough for this project. CloudTrail gives one free trail per region. The only potential cost is API Gateway ($3.50/million calls) and Secrets Manager ($0.40/secret/month) — negligible.

<img width="1900" height="970" alt="1 console aws image" src="https://github.com/user-attachments/assets/b6c131d8-9306-43a3-ac36-c97eff36d5ec" />


</details>

---

<details>
<summary><b>Phase 1 — IAM Roles</b></summary>

<br>

### Goal

Create the 4 IAM roles used by every component in the pipeline. IAM is first because every Lambda and the Step Functions state machine need a role before they can be created. All roles use inline policies — no AWS managed policies, no wildcards on sensitive resources.

Full policies → [iam/iam-roles.md](./iam/iam-roles.md)

### Roles

| Role | Used By | Why |
|---|---|---|
| AegisAnalyzerRole | aegis-analyzer + aegis-scorer | Read resources, write to DynamoDB |
| AegisRemediatorRole | aegis-remediator | Block exposures, send emails, push to Security Hub |
| AegisApprovalRole | aegis-approval | Update DynamoDB, send confirmation email |
| AegisStepFunctionsRole | Step Functions state machine | Invoke the 4 Lambda functions |

### Steps

Repeat for each role:

1. IAM → Roles → **Create role**
2. Trusted entity → AWS Service → **Lambda** (use **Step Functions** for AegisStepFunctionsRole)
3. Skip permissions — click through to the end
4. Name the role → **Create role**
5. Open the created role → **Add permissions → Create inline policy**
6. Switch to **JSON tab** → delete default content → paste the matching policy from `iam/iam-roles.md`
7. Policy name → same as the role → **Create policy**

> If Step Functions throws a CloudWatch logging error later — use **Create new role** in the Step Functions console instead. Then manually add a Lambda invoke inline policy to that auto-created role.

<img width="1892" height="962" alt="2 p1 iam roles" src="https://github.com/user-attachments/assets/efbf48a3-34fb-4c83-bfd6-19a606dc0720" />


</details>

---

<details>
<summary><b>Phase 2 — DynamoDB Table</b></summary>

<br>

### Goal

Create the findings database. Every detected exposure gets stored here with full context — resource ARN, exposure type, risk level, status, and the raw CloudTrail event details. The 4 GSIs allow querying without a full table scan.

Full schema → [dynamodb/dynamodb-schema.md](./dynamodb/dynamodb-schema.md)

### Table Config

Table name
```
aegis-findings
```
Partition key
```
finding_id (String)
```

### Steps

1. DynamoDB → Tables → **Create table**
2. Table name → `aegis-findings`
3. Partition key → `finding_id` (String)
4. Table settings → Customize → Capacity mode → **On-demand**
5. **Create table** → wait for status Active

### Global Secondary Indexes

Table → Indexes tab → **Create index** — repeat 4 times:

| Index Name | Partition Key | Purpose |
|---|---|---|
| status-index | status (String) | Query all findings by status |
| exposure-type-index | exposure_type (String) | Query all PUBLIC_S3, PUBLIC_EC2, etc. |
| resource-index | resource_id (String) | Look up findings by specific resource |
| risk-index | risk_level (String) | Query all CRITICAL findings, etc. |

> Wait for Active status on each GSI before adding the next.

<img width="1916" height="972" alt="3 p2 dydb tables" src="https://github.com/user-attachments/assets/2baf2381-ff10-4b54-af88-d1fb3aa47f89" />
<p></p>
<img width="1916" height="961" alt="4 p2 dydb indexes" src="https://github.com/user-attachments/assets/841c96c1-dce2-40b9-a4f8-c83d30ae8203" />


</details>

---

<details>
<summary><b>Phase 3 — S3 Buckets</b></summary>

<br>

### Goal

Create two storage buckets — one for remediation reports, one for CloudTrail log delivery. Both must have public access fully blocked.

### Buckets

Reports bucket
```
aegis-reports-YOURNAME
```
Trail logs bucket
```
aegis-trail-logs-YOURNAME
```

### Steps

Repeat for each bucket:

1. S3 → **Create bucket**
2. Enter bucket name (must be globally unique — add your name or a unique string)
3. Region → us-east-1
4. Block all public access → **ON**
5. **Create bucket** → copy bucket ARN and save it

> S3 bucket names are global across all AWS accounts. If the name is taken, add a number or date.

<img width="1066" height="339" alt="5 p3 s3 table report" src="https://github.com/user-attachments/assets/9ea62a7e-8a49-4952-a583-e2dc72a8c449" />


</details>

---

<details>
<summary><b>Phase 4 — CloudTrail</b></summary>

<br>

### Goal

Enable API activity logging across the entire account. CloudTrail is the foundation — without it running, the 5 EventBridge rules have nothing to match against. Set to Write-only to avoid noise from Read events.

### Trail Config

Trail name
```
aegis-trail
```
Log group
```
/aws/cloudtrail/aegis
```

### Steps

1. CloudTrail → **Create trail**
2. Trail name → `aegis-trail`
3. Storage location → Create new S3 bucket → `aegis-trail-logs-YOURNAME`
4. CloudWatch Logs → **Enable** → Log group → `/aws/cloudtrail/aegis` → New IAM role → `AegisCWRole`
5. Events → Management events → **Write** only (uncheck Read)
6. **Create trail** → verify green status

> CloudTrail has a propagation delay of 5–15 minutes after enabling. API calls made right after won't appear immediately — this is normal. If Phase 15 test doesn't trigger immediately, wait before assuming something is broken.

<img width="1899" height="954" alt="6 p4 cloudtrail" src="https://github.com/user-attachments/assets/696fae21-4632-4ba7-9d3d-c110a7247e64" />


</details>

---

<details>
<summary><b>Phase 5 — SNS Topic</b></summary>

<br>

### Goal

Create the alert notification channel. SNS handles two things — routing Slack notifications from `aegis-remediator` and delivering CloudWatch alarm alerts.

### Topic Config

Topic name
```
aegis-alerts
```

### Steps

1. SNS → Topics → **Create topic**
2. Type → **Standard**
3. Topic name → `aegis-alerts`
4. **Create topic** → copy Topic ARN and save it
5. Open topic → **Create subscription**
6. Protocol → **Email** → enter your email
7. **Create subscription** → confirm the link in your inbox

> The email subscription here is for CloudWatch alarm notifications. The actual finding alert emails with approve/restore buttons come through SES — that's set up in Phase 6 and 7.

<img width="1919" height="897" alt="7 p5 sns topic" src="https://github.com/user-attachments/assets/dc220c42-b5fd-4850-bba1-a2bbee1ea418" />

</details>

---

<details>
<summary><b>Phase 6 — SES Email Verification</b></summary>

<br>

### Goal

Verify the email identity used to send alert emails. In SES sandbox mode, both sender and recipient must be verified. Can't send to an unverified address.

### Steps

1. SES → Verified identities → **Create identity**
2. Identity type → **Email address**
3. Enter your email → **Create identity**
4. Open your inbox → click the AWS verification link
5. Back in SES → status must show **Verified**

> If you want to send to a different email address, you'd need to request SES production access. For this project, using the same email for both sender and recipient keeps it simple.

<img width="1612" height="600" alt="8 p6 ses varify" src="https://github.com/user-attachments/assets/ba663c2a-4d42-4e4a-8596-5301d3cad1e3" />

</details>

---

<details>
<summary><b>Phase 7 — Secrets Manager</b></summary>

<br>

### Goal

Store all sensitive configuration in one place. The Lambda functions pull these values at runtime — nothing sensitive is hardcoded in the function code.

### Secret Config

Secret name
```
aegis/email-config
```

### Steps

1. Secrets Manager → **Store a new secret**
2. Secret type → **Other type of secret**
3. Add 4 key-value pairs:

| Key | Value |
|---|---|
| sender_email | your verified SES email |
| recipient_email | your verified SES email (same in sandbox) |
| approval_token_secret | any random string — 32+ characters |
| slack_webhook_url | your Slack incoming webhook URL |

4. Next → Secret name → `aegis/email-config`
5. Next → Next → **Store** → copy secret ARN and save it

> The `approval_token_secret` signs the approve/restore URLs. If you change this value after findings are stored, old email links will return 403.

<img width="1905" height="928" alt="9 p7 secret manager" src="https://github.com/user-attachments/assets/0161bde1-2eaa-4fd1-9280-ef331b4258c1" />

</details>

---

<details>
<summary><b>Phase 8 — Lambda Functions</b></summary>

<br>

### Goal

Create the 4 functions that handle detection, scoring, remediation, and approval. All Python 3.12. Create in this order since Step Functions references them by name.

Full code for all 4 → [lambda/lambda-code.md](./lambda/lambda-code.md)

### Functions

| Function | Role | Timeout | What It Does |
|---|---|---|---|
| aegis-analyzer | AegisAnalyzerRole | 1 min | Reads CloudTrail event, identifies exposure, checks for duplicates |
| aegis-scorer | AegisAnalyzerRole | 30 sec | Assigns CRITICAL / HIGH / MEDIUM / LOW |
| aegis-remediator | AegisRemediatorRole | 2 min | Blocks exposure, sends email, notifies Slack, pushes to Security Hub |
| aegis-approval | AegisApprovalRole | 30 sec | Handles approve / restore button clicks |

### Steps

Repeat for each function:

1. Lambda → **Create function** → Author from scratch
2. Runtime → **Python 3.12** | Architecture → x86_64
3. Execution role → **Use an existing role** → select from table above
4. **Create function**
5. Code tab → select all → delete → paste the function code from `lambda/lambda-code.md`
6. Update any `# CONFIGURE:` lines with your actual values
7. Configuration → General configuration → **Edit** → set timeout → Save
8. **Deploy**

> Leave `API_GATEWAY_URL` in aegis-remediator as a placeholder — you'll fill it after Phase 10.

<img width="1901" height="955" alt="10 p8 lambdas" src="https://github.com/user-attachments/assets/715b1d19-2b2c-4334-8c49-c830ecce77f4" />

</details>

---

<details>
<summary><b>Phase 9 — EventBridge Rules</b></summary>

<br>

### Goal

Create 5 rules that watch the account in real time and trigger the pipeline the moment an exposure event is detected. All rules filter out failed API calls using `"errorCode": [{"exists": false}]` to avoid false positives.

Full patterns → [eventbridge/eventbridge-rules.md](./eventbridge/eventbridge-rules.md)

### Rules

| Rule | What It Catches |
|---|---|
| aegis-s3-exposure | S3 bucket policy added, ACL changed, public access block removed |
| aegis-ec2-exposure | EC2 launched with public IP |
| aegis-rds-exposure | RDS created or modified as publicly accessible |
| aegis-alb-exposure | Load balancer created with internet-facing scheme |
| aegis-lambda-url-exposure | Lambda function URL created or updated |

### Steps

Repeat for each rule:

1. EventBridge → Rules → **Create rule**
2. Rule name → (see table) | Event bus → **default**
3. Rule type → **Rule with an event pattern** → Next
4. Event source → AWS events → scroll down → **Custom pattern (JSON editor)**
5. Clear the editor → paste the pattern from `eventbridge/eventbridge-rules.md`
6. Next → Target 1 → **AWS service → Step Functions state machine → aegis-workflow**
7. Execution role → **Create a new role for this specific resource**
8. **Create rule**

> When you select Custom pattern, the Event source dropdown may switch to "Other" — UI quirk, ignore it.

<img width="1896" height="1006" alt="11 p9 eventbridge rules" src="https://github.com/user-attachments/assets/3cce6277-8651-47fa-9539-ca851ea49074" />

</details>

---

<details>
<summary><b>Phase 10 — API Gateway</b></summary>

<br>

### Goal

Create the two endpoints that handle approve and restore button clicks from the alert email. Both route to `aegis-approval`. All URLs are HMAC-signed — invalid tokens return 403.

Full setup → [apigateway/api-gateway.md](./apigateway/api-gateway.md)

### Endpoints

```
GET /approve
GET /restore
```

### Steps

**Create the API:**
1. API Gateway → **Create API → REST API → Build**
2. API name → `aegis-approval-api` | Endpoint type → **Regional**
3. **Create API**

**Create /approve:**
1. Resources → **Create resource** → Resource name → `approve` → Create
2. With `/approve` selected → **Create method → GET**
3. Integration type → **Lambda function** | Lambda proxy integration → **ON**
4. Lambda function → `aegis-approval` → **Create method** → confirm permission

**Create /restore:**
1. Click root `/` → **Create resource** → Resource name → `restore` → Create
2. Repeat same method steps → Lambda → `aegis-approval`

**Deploy:**
1. **Deploy API** → New stage → Stage name → `prod` → Deploy
2. Copy the **Invoke URL** → `https://XXXXXXXXXX.execute-api.us-east-1.amazonaws.com/prod`

**Update aegis-remediator:**
1. Lambda → `aegis-remediator` → Code tab
2. Replace `API_GATEWAY_URL` placeholder with your Invoke URL
3. **Deploy**

<img width="1919" height="980" alt="12 p10 cloud watch" src="https://github.com/user-attachments/assets/1cc8b51a-fdef-4c7c-87d0-47be0dc17c0a" />
<p></p>
<img width="1919" height="980" alt="13 p10 state machine" src="https://github.com/user-attachments/assets/7156262e-e50b-44a9-a926-701be29c0bdf" />

</details>

---

<details>
<summary><b>Phase 11 — Step Functions</b></summary>

<br>

### Goal

Create the state machine that wires all 4 Lambda functions together in a supervised pipeline. Every task state has retry with exponential backoff. Logging is set to ALL level so you can trace exactly what happened in every execution.

Full setup + ASL → [stepfunctions/step-functions.md](./stepfunctions/step-functions.md)

### State Machine Config

Name
```
aegis-workflow
```
Type
```
Standard
```
Log group
```
/aws/states/aegis-workflow
```

### Steps

**Step 1 — Create CloudWatch Log Group:**

1. CloudWatch → Log groups → **Create log group**
2. Name → `/aws/states/aegis-workflow` | Retention → **90 days** → Create
3. Copy the Log Group ARN

Run in **CloudShell** — Step Functions can't write to CloudWatch without this resource policy:

```bash
aws logs put-resource-policy \
  --policy-name AegisStepFunctionsLogPolicy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":["logs:CreateLogDelivery","logs:GetLogDelivery","logs:UpdateLogDelivery","logs:DeleteLogDelivery","logs:ListLogDeliveries","logs:PutLogEvents","logs:PutResourcePolicy","logs:DescribeResourcePolicies","logs:DescribeLogGroups"],"Resource":"*"}]}'
```

**Step 2 — Create State Machine:**

1. Step Functions → **Create state machine**
2. Authoring method → **Write your workflow in code** | Type → **Standard**
3. Clear editor → paste full ASL from `stepfunctions/step-functions.md`
4. Next → Name → `aegis-workflow`
5. Permissions → **Choose an existing role → AegisStepFunctionsRole**
6. Logging → Log level → **ALL** → paste Log Group ARN → Include execution data → ✅
7. **Create state machine** → copy State Machine ARN

> CloudWatch Logs error during creation → use **Create new role** instead. Then go to IAM, find the auto-created role, and add an inline policy with `lambda:InvokeFunction` on all 4 aegis Lambda ARNs.

<img width="1900" height="990" alt="14 p11 api gateway" src="https://github.com/user-attachments/assets/59834e89-0c0f-40be-84bb-7fad4ffcbbfb" />

</details>

---

<details>
<summary><b>Phase 12 — CloudWatch Alarms</b></summary>

<br>

### Goal

Set up 4 alarms that watch for errors and failures across the pipeline. If any Lambda throws an error or the state machine fails, the alarm fires and notifies `aegis-alerts`.

Full config → [cloudwatch/cloudwatch-alarms.md](./cloudwatch/cloudwatch-alarms.md)

### Alarms

| Alarm | Metric | Watches |
|---|---|---|
| aegis-remediator-errors | Lambda Errors — aegis-remediator | Failures in the remediation function |
| aegis-analyzer-errors | Lambda Errors — aegis-analyzer | Failures in the detection function |
| aegis-scorer-errors | Lambda Errors — aegis-scorer | Failures in the scoring function |
| aegis-workflow-failures | Step Functions ExecutionsFailed | Complete pipeline failures |

### Steps

Repeat for each alarm:

1. CloudWatch → Alarms → **Create alarm**
2. **Select metric** → find the metric (see table + cloudwatch-alarms.md)
3. Statistic → **Sum** | Period → **5 minutes**
4. Conditions → Greater than → **0**
5. Notification → In alarm → **aegis-alerts**
6. Alarm name → (see table) → **Create alarm**

<img width="1913" height="960" alt="15 p12 cw alarms" src="https://github.com/user-attachments/assets/dd50c0ae-8125-4fea-8227-2464660b2edb" />

</details>

---

<details>
<summary><b>Phase 13 — AWS Config</b></summary>

<br>

### Goal

Add a second layer of compliance checking that runs independently of the EventBridge pipeline. AWS Config evaluates resources on a schedule — if something slipped past EventBridge, Config will catch it on the next evaluation cycle.

Full setup + CloudShell commands → [config/config-rules.md](./config/config-rules.md)

### Rules

| Rule | What It Checks |
|---|---|
| s3-bucket-public-read-prohibited | S3 buckets with public read access |
| s3-bucket-public-write-prohibited | S3 buckets with public write access |
| rds-instance-public-access-check | RDS with PubliclyAccessible=true |
| restricted-ssh | Security groups with SSH open to 0.0.0.0/0 |
| restricted-common-ports | Security groups with unrestricted common ports |

### Steps

**Enable Config:**

1. AWS Config → **Get started**
2. Recording strategy → All resource types | Frequency → Continuous
3. S3 bucket → `aegis-reports-YOURNAME`
4. SNS topic → `aegis-alerts`
5. IAM role → Create AWS Config service-linked role → **Confirm**

> If the console wizard fails at the recorder step — use the CloudShell commands in `config/config-rules.md`. More reliable.

**Add rules:**

Config → Rules → **Add rule** → search each rule name → Next → Save

Or use CloudShell (faster) — all commands in `config/config-rules.md`.

<img width="1904" height="962" alt="16 p13 config rules" src="https://github.com/user-attachments/assets/404b777f-654a-444c-a373-2c85e66a3aa5" />

</details>

---

<details>
<summary><b>Phase 14 — Security Hub</b></summary>

<br>

### Goal

Enable centralized security findings. Every time `aegis-remediator` runs, it pushes the finding to Security Hub in ASFF format automatically — building a proper audit trail that can be queried, filtered, and eventually integrated with a SIEM.

### Steps

1. Security Hub → **Enable Security Hub**
2. Enable standards:
   - **AWS Foundational Security Best Practices** ✅
   - **CIS AWS Foundations Benchmark** ✅
3. **Enable Security Hub** → wait for it to initialise

After the Phase 15 test, check Security Hub → Findings — the aegis finding will appear there automatically.

<img width="1767" height="1077" alt="17 p14 sec hub" src="https://github.com/user-attachments/assets/05d9f88c-ddca-4366-afce-354e9f2cdb72" />

</details>

---

<details>
<summary><b>Phase 15 — End-to-End Test</b></summary>

<br>

### Goal

Run the full pipeline and confirm every step works — detection, scoring, remediation, email, DynamoDB, Security Hub.

### Setup

Open two browser tabs:
- **Tab 1** → Step Functions → `aegis-workflow` → Executions
- **Tab 2** → S3

### Trigger a Detection

1. S3 → **Create bucket** → name → `aegis-test-YOURNAME`
2. Uncheck Block all public access → acknowledge the warning → Create
3. Open bucket → **Permissions** tab → Bucket policy → **Edit** → paste:

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

4. **Save changes**

Wait 3–15 minutes. CloudTrail propagation delay is normal — the event travels CloudTrail → EventBridge → Step Functions.

### What Should Happen

✅ Tab 1 — New execution appears → Status **Succeeded**

✅ Click execution → **Graph view** → full green pipeline to WorkflowComplete

✅ HTML alert email arrives with two action buttons

✅ Tab 2 → `aegis-test-YOURNAME` → Permissions → Block Public Access back **ON** — auto-remediated

✅ DynamoDB → `aegis-findings` → **Explore items** → new finding row

✅ Security Hub → Findings → new ASFF entry

Click the approve button in the email — confirmation email arrives and finding status in DynamoDB updates to INTENTIONAL.

<p></p>
<img width="1919" height="882" alt="18 p15 test s3" src="https://github.com/user-attachments/assets/c251c1d9-5cb5-4a86-abfd-8cf5f299bdf4" />
<p></p>
<img width="1880" height="964" alt="19 p15 s3 before conf" src="https://github.com/user-attachments/assets/292aefec-cda1-4307-a738-713c2c5faf19" />
<p></p>
<img width="1919" height="988" alt="20 p15 workflow" src="https://github.com/user-attachments/assets/d9a694ad-51da-45e3-9d7c-fbd7f82f60e7" />
<p></p>
<img width="1607" height="891" alt="21 p15 email" src="https://github.com/user-attachments/assets/0aa4a7f9-be06-4494-afbb-42b020b85976" />
<p></p>
<img width="755" height="715" alt="22 p15 email reject" src="https://github.com/user-attachments/assets/f99c91d4-b586-47a4-aafc-83d07d9b9d25" />
<p></p>
<img width="668" height="682" alt="23 p15 email approve" src="https://github.com/user-attachments/assets/b2f47d32-f143-48ce-9e77-984017c0c12c" />
<p></p>
<img width="1889" height="920" alt="24 p16 s3 after conf" src="https://github.com/user-attachments/assets/1b61edd8-9eb1-4fe7-b0e7-f11c4fcbebc5" />
<p></p>
</details>

---

<details>
<summary><b>Troubleshooting</b></summary>

**No execution after 15 minutes** — CloudTrail status Active? EventBridge rule Enabled? State machine ARN correct in the rule target?

**Execution → NoExposureDetected** — Not a failure. Duplicate event or analyzer couldn't confirm exposure. Working as designed.

**Email not arriving** — SES status Verified? Check spam. Both sender and recipient in Secrets Manager must be the same verified email.

**Step Functions CloudWatch error** — Run the CloudShell command in Phase 11. Or use Create new role during state machine creation.

**Config recorder failed** — Use the CloudShell method in config-rules.md.

**403 on approve/restore button** — API_GATEWAY_URL in aegis-remediator doesn't match prod stage URL. Or approval_token_secret changed after findings were stored.



</details>

---

## 🧾 Author

**Ridam Darji**

Cloud Security · AWS · Hands-on builder

[LinkedIn](https://www.linkedin.com/in/ridamdarji/) · [GitHub](https://github.com/ridamdarji25)

---

## License

MIT License
