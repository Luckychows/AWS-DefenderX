## AWS DefenderX

Cloud Misconfiguration Attack Simulator + Auto Remediation Platform.

This repo contains:
- **Local SOC dashboard** (FastAPI + HTML/JS)
- **AWS automated monitoring : CloudTrail/EventBridge + scheduled scanner Lambdas → DynamoDB → API Gateway
- **AI risk summarization** (OpenAI; key stored in AWS Secrets Manager for cloud)
- **Optional outbound integrations** (Splunk/Elastic/webhooks for Wazuh/Suricata/Falco)

- Detects common AWS misconfigurations from **simulated events**
- Stores findings
- Generates an AI risk summary (optional)
- Renders a simple SOC dashboard
- Supports “optional remediation” as a stub (records remediation actions)

AWS monitoring is fully automated via `aws/sam` (no manual log uploads).

### Run locally

Prereqs: Python 3.11+

```bash
cd backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:
- Dashboard: `http://127.0.0.1:8000/`
- API docs: `http://127.0.0.1:8000/docs`

### Quick demo flow

1) Load sample “cloud events”:

```bash
curl -X POST http://127.0.0.1:8000/api/simulate/load-sample
```

2) View findings:

```bash
curl http://127.0.0.1:8000/api/findings
```

3) Generate AI summary for a finding (optional):

```bash
curl -X POST http://127.0.0.1:8000/api/findings/<FINDING_ID>/summarize
```

If you set `OPENAI_API_KEY`, it will call OpenAI by default. Otherwise it uses a deterministic offline summary.

### Integrations (local)

By default, every created finding is also emitted as an “alert event” to a local JSONL file:

- `backend/app/data/alerts.jsonl`

You can additionally emit to Splunk HEC and/or Elastic by setting env vars:

- **Splunk HEC**
  - `ALERT_SINKS=jsonl,splunk`
  - `SPLUNK_HEC_URL` (example: `https://splunk:8088/services/collector`)
  - `SPLUNK_HEC_TOKEN`
  - Optional: `SPLUNK_HEC_INDEX`, `SPLUNK_HEC_SOURCETYPE`

- **Elastic**
  - `ALERT_SINKS=jsonl,elastic`
  - `ELASTIC_URL` (example: `https://elastic:9200`)
  - `ELASTIC_API_KEY`
  - Optional: `ELASTIC_INDEX`

### Local Elastic + Kibana (optional, via Docker)

If you want a real “SIEM-like” place to view alerts without installing anything:

```bash
docker compose up -d
```

Then configure the backend:

- `ALERT_SINKS=jsonl,elastic`
- `ELASTIC_URL=http://127.0.0.1:9200`

Open Kibana at `http://127.0.0.1:5601/`.

### Desktop folder note (Windows)

This environment can only write inside the current workspace directory. When you’re ready to move the finished project to your Desktop, run:

```powershell
Copy-Item -Recurse -Force "C:\Users\lucky\.cursor\projects\empty-window\cloud-misconfig-sim" "$env:USERPROFILE\Desktop\cloud-misconfig-sim"
```

### Deploy to AWS (automated monitoring)

When you’re ready, you’ll replace the local ingest with real AWS signals (Option A = fully automated):

- **AWS Config + CloudTrail**: enable organization-wide if possible
- **EventBridge**: route relevant events to a rule that targets a Lambda
- **Lambda detection engine**: runs detections automatically (no log uploads)
- **Scheduled scanner Lambda**: catches “state” issues (S3/SG/EBS/CloudTrail posture)
- **DynamoDB**: stores findings centrally
- **API Gateway + Lambda**: serves findings + AI summaries

Follow: `aws/README_AWS_SETUP.md`

### Cloud dashboard mode (use deployed AWS API)

You can point the local dashboard UI to the deployed AWS API:

1) Open `backend/app/templates/index.html`
2) Edit `window.CMS_CONFIG`:

```html
window.CMS_CONFIG = {
  apiBaseUrl: "https://<api-id>.execute-api.<region>.amazonaws.com/Prod",
  apiToken: "<ApiAuthToken-from-sam-deploy>",
};
```

3) Restart backend and open `http://127.0.0.1:8000/`

The UI will now read/write against cloud findings instead of local simulator endpoints.

### GitHub safety