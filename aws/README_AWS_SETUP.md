# AWS DefenderX — AWS deployment guide

This file explains **only the AWS side**: what to turn on in the console and how to deploy the serverless stack so your account is monitored **automatically** (no uploading log files).

---

## What gets created in AWS

After a successful `sam deploy` you get:

| Resource | Role |
|----------|------|
| **DynamoDB table** | Stores each finding. |
| **RealtimeDetectorFunction** | Triggered by EventBridge on selected CloudTrail-style events. |
| **PeriodicScannerFunction** | Runs on a schedule; scans S3, EC2 SGs, EBS, CloudTrail status, IAM MFA summary. |
| **ApiFunction + API Gateway** | REST API: `/findings`, `/findings/{id}`, `/summarize`, `/remediate` (auth + flags apply). |
| **EventBridge rules** | Wire CloudTrail-related patterns to the detector Lambda. |

---

## Before you deploy — AWS Console checklist

Do these in the **same region** you plan to deploy (example: `ap-south-2`).

### 1) CloudTrail

- AWS Console → **CloudTrail** → create or use a trail.  
- **Multi-region trail:** On.  
- **Management events:** Read + Write (all).  
- **Logging:** On.

### 2) AWS Config

- Console → **AWS Config** → enable recorder and delivery channel.  
- Prefer **record all resources** and **global resources** where applicable.

### 3) OpenAI key in Secrets Manager

- Console → **Secrets Manager** → **Store a new secret** → **Other**.  
- Add key: **`OPENAI_API_KEY`** → value: your `sk-...` key.  
- Secret name: **`cloud-misconfig/openai`** (must match template default or your override).

### 4) On your system

Install and verify:

- **AWS CLI** — `aws sts get-caller-identity`  
- **AWS SAM CLI** — `sam --version`  
- **Python 3.11** — SAM uses it to build Python 3.11 Lambdas  

From the repo:

```powershell
cd aws\sam
sam build
sam deploy --guided --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM
```

**Important prompts:**

| Parameter | Typical value |
|-----------|----------------|
| Stack name | e.g. `cloud-misconfig-sim-hyd` |
| Region | e.g. `ap-south-2` |
| **ApiAuthToken** | Long random string — required for API calls |
| **EnableAutoRemediation** | `false` unless you accept live AWS changes |
| **EnableSecurityIntegrations** | `true` only if you have real Splunk/Elastic/webhook URLs |
| Permissions boundary | Your org’s ARN if required; else empty |

If deploy fails with **CAPABILITY_NAMED_IAM**, rerun deploy with:

`--capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM`

---

## After deploy — verify

1. **Outputs** — copy **ApiUrl** from CloudFormation / SAM output.  
2. **Test API** (PowerShell):

```powershell
$api="https://YOUR_API.execute-api.REGION.amazonaws.com/Prod"
$tok="YOUR_ApiAuthToken"
Invoke-RestMethod "$api/findings" -Headers @{"x-api-token"=$tok}
```

3. **Lambda** — open **PeriodicScannerFunction** → **Test** → Invoke once → call `/findings` again.  
4. **API Gateway CORS** — if the browser dashboard calls the API, enable CORS for your origin and allow header **`x-api-token`**, then **Deploy** API to **Prod**.

---

## API usage (summary)

All calls below need:

`x-api-token: <ApiAuthToken>`

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/findings` | List findings |
| GET | `/findings/{id}` | One finding |
| POST | `/findings/{id}/summarize` | AI summary (uses Secrets Manager OpenAI key) |
| POST | `/findings/{id}/remediate` | Auto-remediation only if enabled in stack |

---

## Optional: Splunk / Elastic / Wazuh / Suricata / Falco

Set **`EnableSecurityIntegrations=true`** during deploy and fill only the parameters you use:

- **Splunk:** `SplunkHecUrl`, `SplunkHecToken`, optional `SplunkHecIndex`  
- **Elastic:** `ElasticUrl`, optional `ElasticApiKey`, `ElasticIndex`  
- **Webhooks:** `WazuhWebhookUrl`, `SuricataWebhookUrl`, `FalcoWebhookUrl` (+ optional API keys)

Lambda must be able to reach those URLs (public endpoint or VPC routing you configure).

---

## Limits and safety

- Scanner IAM permissions are broad **read** access by design; tighten for production.  
- Auto-remediation can change real resources — keep it off until you trust the rules.  
- **IAM role names** include the stack name so you can deploy multiple stacks without name clashes.

For the full local + cloud story, see the root **[README.md](../README.md)**.
