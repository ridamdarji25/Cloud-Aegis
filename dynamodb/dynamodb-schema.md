# DynamoDB — aegis-findings

Stores every finding with full context. 4 GSIs for querying by status, exposure type, resource, and risk level.

---

## How to Create (AWS Console)

**Create the table:**

1. DynamoDB → Tables → Create table
2. Table name: `aegis-findings`
3. Partition key: `finding_id` (String)
4. Table settings: Customize → Capacity mode: On-demand
5. Create table

**Add 4 GSIs** (Table → Indexes tab → Create index, repeat 4 times):

| Index Name | Partition Key |
|---|---|
| `status-index` | `status` (String) |
| `exposure-type-index` | `exposure_type` (String) |
| `resource-index` | `resource_id` (String) |
| `risk-index` | `risk_level` (String) |

---

## Schema

| Attribute | Type | Example |
|---|---|---|
| `finding_id` | String (PK) | UUID |
| `timestamp` | String | `2024-03-06T18:30:00Z` |
| `resource_arn` | String | `arn:aws:s3:::my-bucket` |
| `resource_id` | String | `my-bucket` |
| `resource_type` | String | `S3` |
| `exposure_type` | String | `PUBLIC_S3` |
| `risk_level` | String | `CRITICAL` |
| `status` | String | `QUARANTINED` |
| `details` | Map | full context object |
| `account_id` | String | AWS account ID |
| `remediated_by` | String | `AUTO` |

Status flow: `DETECTED` → `QUARANTINED` → `APPROVED` / `INTENTIONAL`

---

## Schema Reference

```json
{
  "TableName": "aegis-findings",
  "BillingMode": "PAY_PER_REQUEST",
  "KeySchema": [
    { "AttributeName": "finding_id", "KeyType": "HASH" }
  ],
  "AttributeDefinitions": [
    { "AttributeName": "finding_id",    "AttributeType": "S" },
    { "AttributeName": "status",        "AttributeType": "S" },
    { "AttributeName": "exposure_type", "AttributeType": "S" },
    { "AttributeName": "resource_id",   "AttributeType": "S" },
    { "AttributeName": "risk_level",    "AttributeType": "S" }
  ],
  "GlobalSecondaryIndexes": [
    { "IndexName": "status-index",        "KeySchema": [{ "AttributeName": "status",        "KeyType": "HASH" }], "Projection": { "ProjectionType": "ALL" } },
    { "IndexName": "exposure-type-index", "KeySchema": [{ "AttributeName": "exposure_type", "KeyType": "HASH" }], "Projection": { "ProjectionType": "ALL" } },
    { "IndexName": "resource-index",      "KeySchema": [{ "AttributeName": "resource_id",   "KeyType": "HASH" }], "Projection": { "ProjectionType": "ALL" } },
    { "IndexName": "risk-index",          "KeySchema": [{ "AttributeName": "risk_level",    "KeyType": "HASH" }], "Projection": { "ProjectionType": "ALL" } }
  ]
}
```
