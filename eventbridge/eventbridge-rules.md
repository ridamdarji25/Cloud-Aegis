# EventBridge — Rules

5 rules watching the entire AWS account in real time. All target `aegis-workflow`.

Every rule uses `"errorCode": [{"exists": false}]` to skip failed API calls and avoid false positives.

**How to create each rule:** EventBridge → Rules → Create rule → Event bus: default → Rule with an event pattern → Custom pattern (JSON editor) → paste the pattern → Next → Target: Step Functions → aegis-workflow → Create new role → Create rule

> The Event source toggle may switch to "Other" when you select custom pattern — ignore it, the source field inside the JSON is what matters.

---

## aegis-s3-exposure

Fires when a bucket policy is added, ACLs are changed, public access block is deleted, or static website hosting is enabled.

```json
{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": [
      "PutBucketAcl",
      "PutBucketPolicy",
      "DeleteBucketPublicAccessBlock",
      "PutBucketWebsite"
    ],
    "errorCode": [{"exists": false}]
  }
}
```

---

## aegis-ec2-exposure

Fires on `RunInstances` only when `associatePublicIpAddress` is `true` — private instances are ignored.

```json
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["RunInstances"],
    "errorCode": [{"exists": false}],
    "requestParameters": {
      "networkInterfaceSet": {
        "items": {
          "associatePublicIpAddress": [true]
        }
      }
```

---

## aegis-rds-exposure

Fires when an RDS instance is created or modified with `publiclyAccessible: true`.

```json
{
  "source": ["aws.rds"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["CreateDBInstance", "ModifyDBInstance"],
    "errorCode": [{"exists": false}],
    "requestParameters": {
      "publiclyAccessible": [true]
    }
  }
```

---

## aegis-alb-exposure

Fires when a load balancer is created with `internet-facing` scheme.

```json
{
  "source": ["aws.elasticloadbalancing"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["CreateLoadBalancer"],
    "errorCode": [{"exists": false}],
    "requestParameters": {
      "scheme": ["internet-facing"]
    }
  }
```

---

## aegis-lambda-url-exposure

Fires when a Lambda function URL is created or updated.

```json
{
  "source": ["aws.lambda"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["CreateFunctionUrlConfig","UpdateFunctionUrlConfig"],
    "errorCode": [{"exists": false}],
    "requestParameters": {
      "authType": ["NONE"]
    }
  }
```
