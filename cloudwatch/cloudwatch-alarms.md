# CloudWatch — Alarms

4 alarms. 3 watch Lambda errors, 1 watches Step Functions failures. All send to `aegis-alerts` SNS.

**How to create each:** CloudWatch → Alarms → Create alarm → Select metric → (see each section) → Statistic: Sum | Period: 5 min | Threshold: Greater than 0 → Notification: aegis-alerts → name → Create alarm

---

## aegis-remediator-errors

Metric: Lambda → By Function Name → `aegis-remediator` → Errors
Alarm name: `aegis-remediator-errors`

---

## aegis-analyzer-errors

Metric: Lambda → By Function Name → `aegis-analyzer` → Errors
Alarm name: `aegis-analyzer-errors`

---

## aegis-scorer-errors

Metric: Lambda → By Function Name → `aegis-scorer` → Errors
Alarm name: `aegis-scorer-errors`

---

## aegis-workflow-failures

Metric: Step Functions → ExecutionsFailed → `aegis-workflow`
Alarm name: `aegis-workflow-failures`

---

## Alarm Config Reference

```json
[
  {
    "AlarmName": "aegis-remediator-errors",
    "Namespace": "AWS/Lambda",
    "MetricName": "Errors",
    "Dimensions": [{ "Name": "FunctionName", "Value": "aegis-remediator" }],
    "Statistic": "Sum", "Period": 300, "Threshold": 0,
    "ComparisonOperator": "GreaterThanThreshold",
    "AlarmActions": ["arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:aegis-alerts"]
  },
  {
    "AlarmName": "aegis-analyzer-errors",
    "Namespace": "AWS/Lambda",
    "MetricName": "Errors",
    "Dimensions": [{ "Name": "FunctionName", "Value": "aegis-analyzer" }],
    "Statistic": "Sum", "Period": 300, "Threshold": 0,
    "ComparisonOperator": "GreaterThanThreshold",
    "AlarmActions": ["arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:aegis-alerts"]
  },
  {
    "AlarmName": "aegis-scorer-errors",
    "Namespace": "AWS/Lambda",
    "MetricName": "Errors",
    "Dimensions": [{ "Name": "FunctionName", "Value": "aegis-scorer" }],
    "Statistic": "Sum", "Period": 300, "Threshold": 0,
    "ComparisonOperator": "GreaterThanThreshold",
    "AlarmActions": ["arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:aegis-alerts"]
  },
  {
    "AlarmName": "aegis-workflow-failures",
    "Namespace": "AWS/States",
    "MetricName": "ExecutionsFailed",
    "Dimensions": [{ "Name": "StateMachineArn", "Value": "arn:aws:states:us-east-1:YOUR_ACCOUNT_ID:stateMachine:aegis-workflow" }],
    "Statistic": "Sum", "Period": 300, "Threshold": 0,
    "ComparisonOperator": "GreaterThanThreshold",
    "AlarmActions": ["arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:aegis-alerts"]
  }
]
```
