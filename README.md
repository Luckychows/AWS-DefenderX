# AWS DefenderX

**AWS DefenderX** is a cloud security project that finds risky AWS settings, stores findings, explains risk with AI, and shows everything in a simple SOC-style dashboard. You can run it **only on your laptop** (demo mode) or connect it to a **real AWS account** (automatic monitoring).

---

## What this project does

| Area | What you get |
|------|----------------|
| **Detection** | Public S3 exposure, security groups open to `0.0.0.0/0`, root usage signals, MFA posture, CloudTrail logging state, unencrypted EBS, overly permissive IAM patterns (where modeled). |
| **Storage** | Local: SQLite. AWS: DynamoDB. |
| **UI** | Custom SOC dashboard (browser). |
| **AI** | OpenAI summaries (local `.env` or AWS Secrets Manager in cloud). |
| **AWS automation** | CloudTrail → EventBridge → Lambda, plus a scheduled scanner Lambda. No manual log uploads. |
| **Optional tools** | Forward alerts to Splunk (HEC), Elastic, or generic webhooks (e.g. adapters for Wazuh / Suricata / Falco). |
| **Docker** | Optional: runs **Elasticsearch + Kibana** on your machine only. It does **not** replace Python, AWS CLI, or SAM. |

---

## What you need on your computer

| Software | Required? | Why |
|----------|------------|-----|
| **Python 3.11+** | Yes (for local dashboard + SAM builds) | Backend and Lambda packaging. |
| **Git** | Yes (to clone and push) | Version control. |
| **AWS CLI** | Yes (for AWS deploy) | `aws configure` or SSO. |
| **AWS SAM CLI** | Yes (for AWS deploy) | `sam build` / `sam deploy`. |
| **Docker Desktop** | Optional | Only if you want local Elastic/Kibana from `docker-compose.yml`. |

**Docker does not “handle everything.”** You still need Python for the dashboard; AWS Lambdas run in AWS, not inside your Docker Compose file.

---

## Quick start (after you clone)

### 1) Clone the repository

```bash
git clone https://github.com/Luckychows/AWS-DefenderX.git
cd AWS-DefenderX
```

(Use your real repo URL if the name or owner differs.)

### 2) Run the local dashboard (simulator mode)

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
# Edit .env: set OPENAI_API_KEY=sk-...  (never commit real keys)
uvicorn app.main:app --reload
```

Open **http://127.0.0.1:8000/** — use **Load sample findings** to demo rules locally.

If PowerShell blocks `Activate.ps1`:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### 3) (Optional) Local Elastic + Kibana

From repo root:

```powershell
docker compose up -d
```

Then set in `backend/.env` (or environment): `ALERT_SINKS=jsonl,elastic` and `ELASTIC_URL=http://127.0.0.1:9200`.  
Kibana: **http://127.0.0.1:5601/**

### 4) Connect the dashboard to your deployed AWS API

1. Deploy AWS stack (see **`aws/README_AWS_SETUP.md`**).
2. Edit **`backend/app/templates/index.html`** — set `window.CMS_CONFIG`:

```js
window.CMS_CONFIG = {
  apiBaseUrl: "https://YOUR_API_ID.execute-api.YOUR_REGION.amazonaws.com/Prod",
  apiToken: "YOUR_SAM_PARAMETER_ApiAuthToken",
};
```

3. Restart `uvicorn` and refresh the dashboard.  
   “Load sample” is disabled in cloud mode; findings come from AWS.

---

## What you do in your AWS account (summary)

Do these **once** in the AWS Console (full step-by-step: **`aws/README_AWS_SETUP.md`**):

1. Turn on **CloudTrail** (multi-region, management events, logging on).  
2. Turn on **AWS Config** (recording on).  
3. Create **Secrets Manager** secret `cloud-misconfig/openai` with key **`OPENAI_API_KEY`**.  
4. On your PC: `cd aws/sam` → `sam build` → `sam deploy --guided` (set region, stack name, `ApiAuthToken`, capabilities including **NAMED_IAM** if prompted).  
5. In **API Gateway**, enable **CORS** for your browser origin and header **`x-api-token`**, then **Deploy** to `Prod`.  
6. Invoke **PeriodicScannerFunction** once to see findings immediately.

---

## Project layout (short)

- **`backend/`** — FastAPI app, dashboard, local rules and SQLite.  
- **`aws/sam/`** — SAM template + Lambda code for real AWS monitoring.  
- **`docker-compose.yml`** — Optional local Elastic stack.  


---

## More help

- **Full AWS deploy and parameters:** [`aws/README_AWS_SETUP.md`](aws/README_AWS_SETUP.md)  
- **API in cloud:** all protected routes need header `x-api-token: <your token>`.

---
