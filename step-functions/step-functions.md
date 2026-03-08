# Step Functions — State Machine

The orchestration layer. Connects all 4 Lambda functions in a supervised pipeline with retry logic, error handling, and full CloudWatch logging.

Name: `aegis-workflow` | Type: Standard | Logging: ALL

---

## Flow

```
AnalyzeResource (aegis-analyzer)
    ↓
CheckExposureType
    ├── UNKNOWN   → NoExposureDetected ✅ (benign, skip)
    ├── DUPLICATE → NoExposureDetected ✅ (already handled, skip)
    └── default   → ScoreRisk (aegis-scorer)
                        ↓
                    RemediateAndAlert (aegis-remediator)
                        ↓
                    WorkflowComplete ✅
```

All Task states have Retry with exponential backoff. `NoExposureDetected` is a success state — not a failure.

---

## How to Create (AWS Console)

**Step 1 — Create the CloudWatch Log Group**

1. CloudWatch → Log groups → Create log group
2. Name: `/aws/states/aegis-workflow` | Retention: 90 days → Create
3. Copy the Log Group ARN

Then run in CloudShell (required — CloudWatch needs a resource policy to accept Step Functions logs):

```bash
aws logs put-resource-policy \
  --policy-name AegisStepFunctionsLogPolicy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":["logs:CreateLogDelivery","logs:GetLogDelivery","logs:UpdateLogDelivery","logs:DeleteLogDelivery","logs:ListLogDeliveries","logs:PutLogEvents","logs:PutResourcePolicy","logs:DescribeResourcePolicies","logs:DescribeLogGroups"],"Resource":"*"}]}'
```

**Step 2 — Create the State Machine**

1. Step Functions → Create state machine
2. Authoring method: Write your workflow in code | Type: Standard
3. Delete all code → paste the ASL definition below
4. Next → Name: `aegis-workflow`
5. Permissions: Choose existing role → `AegisStepFunctionsRole`
6. Logging: Level ALL → paste Log Group ARN → Include execution data: ✅
7. Create state machine → copy the ARN

> If Step Functions shows a CloudWatch error → use Create new role instead, then manually add a Lambda invoke inline policy to that auto-created role.

---

## ASL Definition

```json
{
  "Comment": "Cloud Aegis v2 - with Retry and Logging",
  "StartAt": "AnalyzeResource",
  "States": {
    "AnalyzeResource": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "aegis-analyzer",
        "Payload.$": "$"
      },
      "ResultSelector": {"body.$": "$.Payload"},
      "ResultPath": "$.analysis",
      "Retry": [{
        "ErrorEquals": ["Lambda.ServiceException","Lambda.AWSLambdaException","Lambda.TooManyRequestsException","Lambda.SdkClientException"],
        "IntervalSeconds": 2,
        "MaxAttempts": 3,
        "BackoffRate": 2
      }],
      "Catch": [{"ErrorEquals": ["States.ALL"], "Next": "HandleError", "ResultPath": "$.error"}],
      "Next": "CheckExposureType"
    },
    "CheckExposureType": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.analysis.body.exposure_type",
          "StringEquals": "UNKNOWN",
          "Next": "NoExposureDetected"
        },
        {
          "Variable": "$.analysis.body.finding_id",
          "StringEquals": "DUPLICATE",
          "Next": "NoExposureDetected"
        }
      ],
      "Default": "ScoreRisk"
    },
    "ScoreRisk": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "aegis-scorer",
        "Payload.$": "$.analysis.body"
      },
      "ResultSelector": {"body.$": "$.Payload"},
      "ResultPath": "$.scored",
      "Retry": [{
        "ErrorEquals": ["Lambda.ServiceException","Lambda.AWSLambdaException","Lambda.TooManyRequestsException"],
        "IntervalSeconds": 2,
        "MaxAttempts": 3,
        "BackoffRate": 2
      }],
      "Catch": [{"ErrorEquals": ["States.ALL"], "Next": "HandleError", "ResultPath": "$.error"}],
      "Next": "RemediateAndAlert"
    },
    "RemediateAndAlert": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "aegis-remediator",
        "Payload.$": "$.scored.body"
      },
      "ResultSelector": {"body.$": "$.Payload"},
      "ResultPath": "$.remediated",
      "Retry": [{
        "ErrorEquals": ["Lambda.ServiceException","Lambda.AWSLambdaException","Lambda.TooManyRequestsException"],
        "IntervalSeconds": 5,
        "MaxAttempts": 2,
        "BackoffRate": 2
      }],
      "Catch": [{"ErrorEquals": ["States.ALL"], "Next": "HandleError", "ResultPath": "$.error"}],
      "Next": "WorkflowComplete"
    },
    "NoExposureDetected": {
      "Type": "Succeed",
      "Comment": "Not a real security exposure - duplicate or benign event"
    },
    "WorkflowComplete": {
      "Type": "Succeed",
      "Comment": "Exposure detected, scored, remediated, alerted"
    },
    "HandleError": {
      "Type": "Fail",
      "Cause": "Aegis workflow failed after retries",
      "Error": "AegisError"
    }
  }
```
