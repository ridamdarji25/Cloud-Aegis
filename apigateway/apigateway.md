# API Gateway — aegis-approval-api

REST API with two endpoints. Both handled by `aegis-approval` Lambda. All approval URLs are HMAC-SHA256 signed — anyone without the valid token gets 403.

Endpoints:
- `GET /approve?finding_id=xxx&action=intentional&token=xxx`
- `GET /restore?finding_id=xxx&action=restore&token=xxx`

---

## How to Create (AWS Console)

**Step 1 — Create the API**

1. API Gateway → Create API → REST API → Build
2. API name: `aegis-approval-api`
3. Endpoint Type: **Regional** → Create API

**Step 2 — Create /approve**

1. Resources → Create resource
2. Resource name: `approve` → Create resource
3. With `/approve` selected → Create method → GET
4. Integration type: Lambda function | Lambda proxy integration: ON
5. Lambda function: `aegis-approval` → Create method

**Step 3 — Create /restore**

1. Click root `/` → Create resource
2. Resource name: `restore` → Create resource
3. With `/restore` selected → Create method → GET
4. Same settings → Lambda: `aegis-approval` → Create method

**Step 4 — Deploy**

1. Deploy API → New stage → Stage name: `prod` → Deploy
2. Copy the Invoke URL: `https://XXXXXXXXXX.execute-api.us-east-1.amazonaws.com/prod`

**Step 5 — Update aegis-remediator**

1. Lambda → `aegis-remediator` → Code tab
2. Replace `API_GATEWAY_URL` placeholder with your Invoke URL
3. Click Deploy

---

## Config Reference

```json
{
  "api_name": "aegis-approval-api",
  "endpoint_type": "REGIONAL",
  "stage": "prod",
  "resources": [
    {
      "path": "/approve",
      "method": "GET",
      "integration": "AWS_PROXY",
      "lambda": "aegis-approval"
    },
    {
      "path": "/restore",
      "method": "GET",
      "integration": "AWS_PROXY",
      "lambda": "aegis-approval"
    }
  ]
}
```
