## AWS Option A (Fully Automated) Setup

Goal: **no manual log uploads**, continuous monitoring of your AWS account.

This deployment creates:
- EventBridge rules → **Realtime detector Lambda**
- Scheduled EventBridge rule → **Periodic scanner Lambda**
- DynamoDB table → stores findings
- API Gateway + Lambda → list/get findings for the dashboard/API
- API token auth header (`x-api-token`) for API access control
- Optional in-place auto-remediation endpoint (feature-flagged)
- Optional outbound integrations to Splunk/Elastic/Wazuh/Suricata/Falco (feature-flagged)

### What you do in AWS Console (step-by-step)

#### 1) Pick a region
Choose one “home” region for the stack (example: `us-east-1`). Deploy everything there.

#### 2) Enable CloudTrail (needed for real-time API activity)
Console → **CloudTrail**:
- Create a trail (or edit existing)
- **Multi-region trail**: ON
- **Management events**: Read/Write = All
- (Recommended) Insight events: optional
- Make sure it is **logging**

This enables “AWS API Call via CloudTrail” events to appear in EventBridge.

#### 3) Enable AWS Config (needed for configuration drift visibility)
Console → **AWS Config**:
- Set up AWS Config
- Recording: ON (all resources)
- Delivery: to an S3 bucket (Config will guide you)

Config isn’t strictly required for the MVP to work (CloudTrail + scanner covers a lot),
but it improves detection and makes the system more enterprise-realistic.

#### 4) Create an OpenAI secret in Secrets Manager
Console → **Secrets Manager** → Store a new secret:
- Secret type: “Other type of secret”
- Key/value: `OPENAI_API_KEY` = `<your key>`
- Name: `cloud-misconfig/openai`

#### 5) Deploy the stack (SAM)
You will run these locally (not in AWS Console):
- Install AWS CLI and authenticate (`aws configure` or SSO)
- Install AWS SAM CLI

From repo root:

```bash
cd aws/sam
sam build
sam deploy --guided
```

During `--guided`:
- Stack name: `cloud-misconfig-sim`
- Region: your chosen region
- Confirm changes: yes
- Allow SAM to create roles: yes
- `ApiAuthToken`: set a strong random value (store safely)
- `EnableAutoRemediation`: set `true` only if you want API-triggered fixes
- `EnableSecurityIntegrations`: set `true` to forward findings to tools
- For each tool, set endpoint/token params you actually use:
  - `SplunkHecUrl`, `SplunkHecToken`, `SplunkHecIndex`
  - `ElasticUrl`, `ElasticApiKey` (optional for non-auth clusters), `ElasticIndex`
  - `WazuhWebhookUrl`, `WazuhApiKey`
  - `SuricataWebhookUrl`, `SuricataApiKey`
  - `FalcoWebhookUrl`, `FalcoApiKey`

#### 6) Verify it is monitoring automatically
Console → **Lambda**:
- `RealtimeDetectorFunction` should show invocations after AWS activity
- `PeriodicScannerFunction` will run every 15 minutes

Console → **DynamoDB**:
- Table `cloud-misconfig-findings` will fill with findings

Console → **API Gateway**:
- Use the output URL from `sam deploy` for:
  - `GET /findings`
  - `GET /findings/{id}`
  - `POST /findings/{id}/summarize`
  - `POST /findings/{id}/remediate`

All API requests must include header:

`x-api-token: <ApiAuthToken>`

### Security tool integration notes

- **Splunk**: uses HEC endpoint (`/services/collector`) with `Authorization: Splunk <token>`.
- **Elastic**: indexes to `/{index}/_doc` with optional `ApiKey`.
- **Wazuh / Suricata / Falco**: sent as JSON webhook payloads to provided URLs (recommended: route via your collector/adapter endpoint).

### Notes
- This is least-privilege oriented, but the scanner needs read permissions across IAM, EC2, S3, CloudTrail.
- Auto-remediation is **disabled by default**. If enabled, only a small set of safe remediations is executed:
  - S3: apply Block Public Access
  - Security Group: revoke captured open ingress rule
  - CloudTrail: attempt StartLogging on trails

