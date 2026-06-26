# Real-World Validation Demo

> **Audience:** Managers, evaluators, and anyone presenting this platform.
> **Estimated time:** 30–45 minutes end-to-end (Azure resource discovery + LLM reasoning dominate).
> **Prerequisite reading time:** 10 minutes.

This guide walks through every phase of the AI-Powered Azure WAF Review Agent running against a live Azure subscription — from environment boot to a downloadable enterprise report. Every command in this document calls an actual project endpoint, reads actual container output, or queries actual database tables. Nothing is simulated.

---

## 1. Executive Overview

The platform automates the Microsoft Azure Well-Architected Framework (WAF) review process across all **five WAF pillars**: Security, Reliability, Operational Excellence, Performance Efficiency, and Cost Optimization. A consultant typically takes two to three days to manually evaluate one subscription across all pillars. This platform does it in under 45 minutes, producing a **29-sheet Excel workbook** and a **33-section PDF** that are fully traceable to the Azure resources that were evaluated.

**What gets demonstrated:**
- Real Azure subscription discovery via Azure Resource Graph KQL
- Real resource property extraction (TLS versions, SKUs, backup settings, encryption flags, diagnostic settings, replication policies, VM sizes, cost tags)
- Real WAF rule evaluation across all 5 pillars — both deterministic DSL (87 rules) and Gemini LLM for complex controls
- Real finding generation with evidence JSON for every finding
- Human Review integration for four controls that cannot be automated
- Enterprise reporting: Executive Summary, Security Scorecard, Business Impact Analysis, Remediation Roadmaps, WAF Traceability Matrix, Trend Analysis, Architecture Topology, and 21 additional sections
- Azure Blob Storage upload of generated reports using Managed Identity

---

## 2. Architecture Overview

The platform is a four-agent Service Bus pipeline backed by PostgreSQL:

```
POST /v1/assessments
         │
         ▼
[API] ──publishes──► assessment.created queue
                              │
                              ▼
                    [Preparation Agent]
                    Discovers resources via Azure Resource Graph KQL
                    Creates batches of 50 resources each
                    Publishes extraction.requested per batch
                    Transitions assessment: pending → preparing → extracting
                              │
                              ▼
                    [Extraction Agent]  (fan-out, one per batch)
                    Fetches full ARM property sets from Resource Graph
                    Stores raw_properties in assessment_resources table
                    Publishes reasoning.requested per batch
                              │
                              ▼
                    [Reasoning Agent]  (fan-out, one per batch)
                    Evaluates each resource against 87 WAF rules:
                      - Deterministic DSL (condition_dsl expressions)
                      - Gemini LLM (llm / hybrid rules)
                      - Azure Advisor (advisor_mapped rules)
                    Inserts findings into assessment_findings table
                    Atomic fan-in: last batch transitions → reporting,
                    then publishes reporting.requested
                              │
                              ▼
                    [Reporting Agent]
                    Aggregates findings from DB
                    Generates 29-sheet Excel + 33-section PDF
                    Uploads both to Azure Blob Storage (Managed Identity)
                    Transitions assessment → completed
```

**Infrastructure (Docker Compose, `--profile full`):**

| Container | Purpose |
|---|---|
| `wafagent-postgres` | PostgreSQL 16 — application state |
| `wafagent-redis` | Redis 7 — quota and rate-limit cache |
| `wafagent-sqledge` | Azure SQL Edge — Service Bus emulator backend |
| `wafagent-servicebus-healthtools` | One-shot init — copies `nc` binary for Service Bus health check |
| `wafagent-servicebus` | Azure Service Bus Emulator |
| `wafagent-mock-azure` | WireMock stub — ARM API responses for extraction tests |
| `wafagent-migrate` | One-shot Alembic migration runner — exits 0 on success |
| `wafagent-api` | FastAPI API server (port 8000) |
| `wafagent-preparation` | Preparation Agent consumer |
| `wafagent-extraction` | Extraction Agent consumer |
| `wafagent-reasoning` | Reasoning Agent consumer |
| `wafagent-reporting` | Reporting Agent consumer |

**Service Bus queues (configured in `docker/servicebus_config.json`):**

| Queue | Lock Duration | Max Deliveries |
|---|---|---|
| `assessment.created` | 5 min | 5 |
| `extraction.requested` | 5 min | 5 |
| `reasoning.requested` | 5 min | 5 |
| `reporting.requested` | 5 min | 5 |
| `assessment.cancelled` | 1 min | 3 |
| `webhook.delivery` | 2 min | 10 |

---

## 3. Prerequisites

| Requirement | Minimum Version | Verification Command |
|---|---|---|
| Docker Desktop | 24.x | `docker --version` |
| Azure CLI | 2.60+ | `az --version` |
| PowerShell | 7.x | `$PSVersionTable.PSVersion` |
| Azure subscription | Any paid or MSDN | `az account show` |
| Gemini API key | Free tier | https://aistudio.google.com/app/apikey |

### 3.1 Azure infrastructure required before the demo

The following must exist in your Azure environment **before** running the demo.

**a) Service principal for resource discovery**

```powershell
$subscriptionId = az account show --query id -o tsv
Write-Host "Subscription: $subscriptionId"

$spName = "sp-waf-agent-demo"
$sp = az ad sp create-for-rbac `
    --name $spName `
    --role "Reader" `
    --scopes "/subscriptions/$subscriptionId" `
    --output json | ConvertFrom-Json

$spClientId     = $sp.appId
$spClientSecret = $sp.password
$spTenantId     = $sp.tenant

Write-Host "SP Client ID:  $spClientId"
Write-Host "SP Tenant ID:  $spTenantId"
```

**b) Key Vault**

The agents read service principal credentials from Key Vault at runtime. Store the SP credentials as a JSON secret:

```powershell
$kvName     = "kv-waf-yoursuffix"   # replace with your Key Vault name
$secretName = "sp-demo-sub-$($subscriptionId.Replace('-','').Substring(0,8))"

$secretValue = @{
    tenant_id     = $spTenantId
    client_id     = $spClientId
    client_secret = $spClientSecret
} | ConvertTo-Json -Compress

az keyvault secret set `
    --vault-name $kvName `
    --name $secretName `
    --value $secretValue

Write-Host "Key Vault secret name: $secretName"
```

Grant the platform identity Key Vault Secrets User so the agents can read the secret at runtime:

```powershell
$kvResourceId = az keyvault show --name $kvName --query id -o tsv

az role assignment create `
    --assignee $spClientId `
    --role "Key Vault Secrets User" `
    --scope $kvResourceId
```

> **Save `$secretName`.** You will use it in step 6.3 to register the credential in the database.

**c) Azure Storage account**

The Reporting Agent uploads generated reports here. Grant the service principal **Storage Blob Data Contributor** on the storage account:

```powershell
$storageAccount = "stwafyoursuffix"    # replace with your storage account name
$storageRg      = "rg-wafagent-demo"

az role assignment create `
    --assignee $spClientId `
    --role "Storage Blob Data Contributor" `
    --scope "/subscriptions/$subscriptionId/resourceGroups/$storageRg/providers/Microsoft.Storage/storageAccounts/$storageAccount"
```

---

## 4. Pre-Demo Verification Checklist

Run every command in this section **before the manager meeting starts**. Each command is designed to fail fast with a clear message.

### 4.1 Azure authentication

```powershell
az login
$subscriptionId = (az account show --query id -o tsv)
az account show --query "{name:name, id:id, tenantId:tenantId}" -o table
```

**Expected:** Your subscription name and ID appear. No errors.

### 4.2 Environment file

```powershell
Get-Content .env | Select-String -Pattern "^(APP_ENV|API_AUTH_MODE|AZURE_TENANT_ID|AZURE_CLIENT_ID|KEYVAULT_URI|STORAGE_ACCOUNT_NAME|GEMINI_API_KEY|LLM_PROVIDER)" | Sort-Object
```

**Expected:** All eight variables are set. `API_AUTH_MODE=development` for demo. `GEMINI_API_KEY` is not empty.

**Common failure:** `GEMINI_API_KEY` is blank → the Reasoning Agent cannot call Gemini for LLM-assisted rules. Fix: add the key to `.env` and restart the reasoning container.

### 4.3 Docker — all containers running

```powershell
docker compose -f docker-compose.dev.yml --profile full ps --format "table {{.Name}}\t{{.Status}}"
```

**Expected output:**
```
NAME                             STATUS
wafagent-sqledge                 Up (healthy)
wafagent-servicebus-healthtools  Exited (0)
wafagent-migrate                 Exited (0)
wafagent-servicebus              Up (healthy)
wafagent-postgres                Up (healthy)
wafagent-redis                   Up (healthy)
wafagent-mock-azure              Up
wafagent-api                     Up
wafagent-preparation             Up
wafagent-extraction              Up
wafagent-reasoning               Up
wafagent-reporting               Up
```

> `wafagent-servicebus-healthtools` and `wafagent-migrate` showing `Exited (0)` are correct — both are one-shot init containers that exit on success.

**Failure:** Any container shows `Exited (1)` or `unhealthy`. Fix: `docker compose -f docker-compose.dev.yml --profile full logs <container-name> --tail 50`.

### 4.4 API liveness

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/healthz"
```

**Expected:** `{"status":"ok"}`

### 4.5 API readiness (database + redis)

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/readyz"
```

**Expected:** `{"status":"ok","checks":{"database":"ok","redis":"ok"}}`

**Failure — `"database":"unreachable"`:** PostgreSQL migrations may still be running. Wait 15 seconds and retry. If still failing: `docker logs wafagent-api --tail 30 | Select-String "alembic|migration|error"`.

### 4.6 Key Vault accessibility and credential secret

```powershell
$kvUri  = (Get-Content .env | Select-String "^KEYVAULT_URI=").ToString().Split("=",2)[1].Trim()
$kvName = $kvUri -replace "https://(.+)\.vault\.azure\.net/?", '$1'
az keyvault secret list --vault-name $kvName --query "[].name" -o table
```

**Expected:** Your Key Vault secrets are listed, including the SP secret created in step 3.1b.

Verify the credential secret exists:

```powershell
$expectedSecret = "sp-demo-sub-$($subscriptionId.Replace('-','').Substring(0,8))"
$found = az keyvault secret show --vault-name $kvName --name $expectedSecret --query name -o tsv 2>$null
if ($found) {
    Write-Host "[OK] Secret '$expectedSecret' exists in Key Vault" -ForegroundColor Green
} else {
    Write-Host "[MISSING] '$expectedSecret' not found — run step 3.1b to create it" -ForegroundColor Red
}
```

**Expected:** `[OK] Secret 'sp-demo-sub-XXXXXXXX' exists in Key Vault`

### 4.7 Gemini API key validity

```powershell
$geminiKey = (Get-Content .env | Select-String "^GEMINI_API_KEY=").ToString().Split("=",2)[1].Trim()
$testUrl = "https://generativelanguage.googleapis.com/v1beta/models?key=$geminiKey"
try {
    $models = Invoke-RestMethod -Uri $testUrl
    Write-Host "Gemini API key valid. Models available: $($models.models.Count)" -ForegroundColor Green
} catch {
    Write-Host "Gemini API key INVALID: $_" -ForegroundColor Red
}
```

**Expected:** `Gemini API key valid. Models available: N`

### 4.8 Blob Storage accessibility

```powershell
$storageAccount = (Get-Content .env | Select-String "^STORAGE_ACCOUNT_NAME=").ToString().Split("=")[1].Trim()
$container = (Get-Content .env | Select-String "^STORAGE_REPORTS_CONTAINER=").ToString().Split("=")[1].Trim()
if (-not $container) { $container = "reports" }

az storage container show `
    --name $container `
    --account-name $storageAccount `
    --auth-mode login `
    --query "name" -o tsv
```

**Expected:** `reports` (or your configured container name).

**Failure:** Container does not exist → create it: `az storage container create --name $container --account-name $storageAccount --auth-mode login`.

---

## 5. Environment Setup

### 5.1 Configure the environment file

The `.env` file at the repository root controls all components. Copy from example if not yet done:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

For the demo, ensure these values are set:

```powershell
# Required: Azure identity for agents to authenticate to Azure APIs
# AZURE_TENANT_ID=<your-azure-tenant-id>
# AZURE_CLIENT_ID=<your-service-principal-client-id>
# AZURE_CLIENT_SECRET=<your-service-principal-client-secret>

# Required: Key Vault holding the cross-tenant SP credentials
# KEYVAULT_URI=https://<your-keyvault>.vault.azure.net/

# Required: Gemini for LLM-assisted rule evaluation (free API key)
# LLM_PROVIDER=gemini
# GEMINI_API_KEY=<your-gemini-key>
# GEMINI_CHAT_MODEL=gemini-2.5-pro

# Required: Azure Blob Storage for report upload
# STORAGE_ACCOUNT_NAME=<your-storage-account>
# STORAGE_REPORTS_CONTAINER=reports

# Demo mode — disables JWT requirement for API calls
# API_AUTH_MODE=development
# APP_ENV=development
```

Verify critical variables are set:

```powershell
$required = @("AZURE_TENANT_ID","AZURE_CLIENT_ID","AZURE_CLIENT_SECRET",
              "KEYVAULT_URI","GEMINI_API_KEY","STORAGE_ACCOUNT_NAME")
foreach ($v in $required) {
    $line = Get-Content .env | Select-String "^${v}=" | Select-Object -First 1
    $val  = if ($line) { $line.ToString().Split("=",2)[1].Trim() } else { "" }
    $status = if ($val -and $val -ne "changeme_local_only") { "[OK]" } else { "[MISSING]" }
    Write-Host "$status $v"
}
```

**Expected:** Every variable shows `[OK]`.

> **Important:** The `API_AUTH_MODE` variable defaults to `entra` (JWT enforcement) in `docker-compose.dev.yml`. For the demo you must set `API_AUTH_MODE=development` either in `.env` or as a shell environment variable before starting containers. Without it, every API call returns 401.

### 5.2 Start all platform services

```powershell
$env:API_AUTH_MODE = "development"
$env:APP_ENV       = "development"

docker compose -f docker-compose.dev.yml --profile full up -d --build
```

This builds images from source and starts all 12 containers. First build takes 3–5 minutes; subsequent starts take under 30 seconds.

Wait for all health checks to pass:

```powershell
$start = Get-Date
do {
    Start-Sleep -Seconds 3
    $statuses = docker compose -f docker-compose.dev.yml --profile full ps --format json |
        ForEach-Object { $_ | ConvertFrom-Json }
    $notReady = $statuses | Where-Object {
        $_.State -eq "exited" -and $_.ExitCode -ne 0
    }
    $unhealthy = $statuses | Where-Object {
        $_.Health -eq "unhealthy" -or $_.Health -eq "starting"
    }
    $elapsed = [int]((Get-Date) - $start).TotalSeconds
    if ($notReady -or $unhealthy) {
        $names = ($notReady + $unhealthy).Name -join ", "
        Write-Host "[${elapsed}s] Waiting for: $names"
    }
} while ($notReady -or $unhealthy)
Write-Host "All services ready." -ForegroundColor Green
```

---

## 6. Preparing a Real Assessment

### 6.1 Create non-compliant Azure resources across multiple WAF pillars

This step creates resources with deliberate WAF violations so the platform has real misconfigurations to detect across multiple pillars. Skip this step if your subscription already has resources.

```powershell
$subscriptionId = (az account show --query id -o tsv)
$resourceGroup  = "rg-waf-demo6"
$location       = "southeastasia"
$weakStorage    = "stwafweak$(Get-Random -Maximum 9999)"

az group create --name $resourceGroup --location $location

# Security violations: TLS 1.0, public blob access enabled, HTTPS not enforced
az storage account create `
    --name $weakStorage `
    --resource-group $resourceGroup `
    --location $location `
    --sku Standard_LRS `
    --kind StorageV2 `
    --min-tls-version TLS1_0 `
    --allow-blob-public-access true `
    --https-only false

Write-Host "Created storage account: $weakStorage"
Write-Host ""
Write-Host "Note: Additional findings across Reliability, Operational Excellence,"
Write-Host "Performance Efficiency, and Cost Optimization pillars will be generated"
Write-Host "from existing resources already present in your subscription."
```

> **Azure Policy note:** If the create command fails with `RequestDisallowedByPolicy`, your subscription enforces security baselines. Use an existing storage account or a development subscription without these policies.

Confirm the non-compliant Storage Account configuration (screenshot checkpoint 1):

```powershell
az storage account show `
    --name $weakStorage `
    --resource-group $resourceGroup `
    --query "{name:name, minimumTlsVersion:minimumTlsVersion, allowBlobPublicAccess:allowBlobPublicAccess, enableHttpsTrafficOnly:enableHttpsTrafficOnly}" `
    -o table
```

**Expected (three Security pillar violations):**
```
Name             MinimumTlsVersion    AllowBlobPublicAccess    EnableHttpsTrafficOnly
---------------  -------------------  -----------------------  ------------------------
stwafweak1234    TLS1_0               True                     False
```

### 6.2 Store service principal credentials in Key Vault

> **Skip if already done in step 3.1b.**

```powershell
$azureTenantId  = (az account show --query tenantId -o tsv)
$spClientId     = (Get-Content .env | Select-String "^AZURE_CLIENT_ID=").ToString().Split("=",2)[1].Trim()
$spClientSecret = (Get-Content .env | Select-String "^AZURE_CLIENT_SECRET=").ToString().Split("=",2)[1].Trim()
$kvUri          = (Get-Content .env | Select-String "^KEYVAULT_URI=").ToString().Split("=",2)[1].Trim()
$kvName         = $kvUri -replace "https://(.+)\.vault\.azure\.net/?", '$1'

$secretName  = "sp-demo-sub-$($subscriptionId.Replace('-','').Substring(0,8))"
$secretValue = @{
    tenant_id     = $azureTenantId
    client_id     = $spClientId
    client_secret = $spClientSecret
} | ConvertTo-Json -Compress

az keyvault secret set `
    --vault-name $kvName `
    --name $secretName `
    --value $secretValue

Write-Host "Secret stored: $secretName"
```

### 6.3 Register the credential in the database

The Preparation Agent requires a `subscription_credentials` row before it will process any assessment. This is a one-time setup per subscription.

```powershell
$subscriptionId = (az account show --query id -o tsv)
$tenantId       = "00000000-0000-0000-0000-000000000001"   # dev tenant, auto-seeded by API
$secretName     = "sp-demo-sub-$($subscriptionId.Replace('-','').Substring(0,8))"

$sql = @"
INSERT INTO subscription_credentials
    (id, tenant_id, subscription_id, display_name, keyvault_secret_name, health, created_at, updated_at)
VALUES
    (gen_random_uuid(),
     '$tenantId',
     '$subscriptionId',
     'Demo Subscription',
     '$secretName',
     'healthy',
     NOW(), NOW())
ON CONFLICT (tenant_id, subscription_id) DO UPDATE
    SET keyvault_secret_name = EXCLUDED.keyvault_secret_name,
        health               = 'healthy',
        updated_at           = NOW();
"@

docker exec -i wafagent-postgres psql -U wafagent -d wafagent -c $sql
Write-Host "Credential registered for subscription $subscriptionId"
```

Verify it was written:

```powershell
docker exec -i wafagent-postgres psql -U wafagent -d wafagent -c `
    "SELECT subscription_id, display_name, health, keyvault_secret_name FROM subscription_credentials WHERE tenant_id='$tenantId';"
```

**Expected:**
```
             subscription_id              |   display_name    | health  |      keyvault_secret_name
--------------------------------------+-------------------+---------+------------------------------------
 xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | Demo Subscription | healthy | sp-demo-sub-xxxxxxxx
```

> **If this step is skipped**, the assessment will fail in `preparing` with log:
> `"event":"preparation.handler.failed","error_type":"InvalidAssessmentScopeError","error_message":"No credential registered for subscription ..."`

---

## 7. Running a Real Assessment

### 7.1 Create the assessment

`API_AUTH_MODE=development` auto-seeds the development tenant (`00000000-0000-0000-0000-000000000001`) and injects `PLATFORM_ADMIN` credentials on every request. No token or tenant registration is needed.

The assessment targets all five WAF pillars in a single run. Remove any pillar from `pillar_filter` to focus the evaluation.

```powershell
$subscriptionId = (az account show --query id -o tsv)
$tenantId = "00000000-0000-0000-0000-000000000001"
$headers  = @{ "Content-Type" = "application/json" }

$body = @{
    idempotency_key  = "demo-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    subscription_ids = @($subscriptionId)
    pillar_filter    = @(
        "Security",
        "Reliability",
        "Operational Excellence",
        "Performance Efficiency",
        "Cost Optimization"
    )
    tag_filter       = $null
} | ConvertTo-Json

$assessment = Invoke-RestMethod `
    -Method POST `
    -Uri "http://localhost:8000/v1/assessments" `
    -Headers $headers `
    -Body $body

$assessmentId = $assessment.id
Write-Host "Assessment ID:  $assessmentId"
Write-Host "Tenant ID:      $($assessment.tenant_id)"
Write-Host "Status:         $($assessment.status)"
```

**Expected response (HTTP 202 Accepted):**
```json
{
  "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "idempotency_key": "demo-20260625-143012",
  "status": "pending",
  "subscription_ids": ["xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"],
  "pillar_filter": [
    "Security",
    "Reliability",
    "Operational Excellence",
    "Performance Efficiency",
    "Cost Optimization"
  ],
  "tag_filter": null,
  "requested_by_oid": "00000000-0000-0000-0000-000000000002",
  "total_batches": null,
  "completed_batches": 0,
  "cancellation_requested_at": null,
  "created_at": "2026-06-25T14:30:12.000Z",
  "updated_at": "2026-06-25T14:30:12.000Z"
}
```

> **Screenshot checkpoint 2:** Capture this response showing `"status":"pending"` and the assessment UUID.

---

## 8. Assessment Lifecycle Monitoring

The assessment transitions through five observable stages:

```
pending → preparing → extracting → reporting → completed
```

- **pending:** API accepted the request; `assessment.created` event published to Service Bus.
- **preparing:** Preparation Agent is querying Azure Resource Graph and creating resource batches.
- **extracting:** Extraction Agent is fetching full ARM properties per batch. The Reasoning Agent evaluates WAF rules concurrently during this window — both run inside `extracting`. The assessment transitions directly from `extracting` to `reporting` when the last reasoning batch completes.
- **reporting:** Reporting Agent is generating the 29-sheet Excel workbook and 33-section PDF.
- **completed:** Both report files uploaded to Azure Blob Storage.

Additional states: `failed` (complete pipeline failure), `cancelled` (operator-requested cancellation), `partial_failure` (some batches failed — assessment may still complete partially).

Run the polling loop below to watch every transition:

```powershell
$previousStatus = ""
$startTime = Get-Date

do {
    $result = Invoke-RestMethod -Uri "http://localhost:8000/v1/assessments/$assessmentId"
    $status = $result.status
    $elapsed = [int]((Get-Date) - $startTime).TotalSeconds

    if ($status -ne $previousStatus) {
        Write-Host "[+${elapsed}s] $previousStatus → $status" -ForegroundColor Cyan
        switch ($status) {
            "preparing"  {
                Write-Host "  Preparation Agent: discovering Azure resources via Resource Graph KQL" -ForegroundColor Gray
            }
            "extracting" {
                Write-Host "  Extraction + Reasoning Agents: fetching ARM properties, evaluating 87 WAF rules (DSL + Gemini LLM)" -ForegroundColor Gray
            }
            "reporting"  {
                Write-Host "  Reporting Agent: generating 29-sheet Excel + 33-section PDF" -ForegroundColor Gray
            }
            "completed"  {
                Write-Host "  Assessment complete. Both reports uploaded to Azure Blob Storage." -ForegroundColor Green
            }
            "partial_failure" {
                Write-Host "  Partial failure: some batches failed. See step 17 (Troubleshooting)." -ForegroundColor Yellow
            }
            "failed"     {
                Write-Host "  Assessment failed. See step 17 (Troubleshooting)." -ForegroundColor Red
            }
        }
        $previousStatus = $status
    }

    if ($status -notin @("completed","failed","cancelled","partial_failure")) {
        Start-Sleep -Seconds 8
    }
} while ($status -notin @("completed","failed","cancelled","partial_failure"))

Write-Host ""
Write-Host "Final status:      $status"
Write-Host "Total batches:     $($result.total_batches)"
Write-Host "Completed batches: $($result.completed_batches)"
```

**Expected terminal output (timing varies with subscription size):**
```
[+0s]    → pending
[+5s]    pending → preparing
  Preparation Agent: discovering Azure resources via Resource Graph KQL
[+20s]   preparing → extracting
  Extraction + Reasoning Agents: fetching ARM properties, evaluating 87 WAF rules (DSL + Gemini LLM)
[+115s]  extracting → reporting
  Reporting Agent: generating 29-sheet Excel + 33-section PDF
[+145s]  reporting → completed
  Assessment complete. Both reports uploaded to Azure Blob Storage.

Final status:      completed
Total batches:     3
Completed batches: 3
```

> **Note:** The `extracting` phase spans both the Extraction Agent (ARM property fetching) and the Reasoning Agent (WAF rule evaluation and finding generation). No intermediate status appears between these two. The transition to `reporting` fires when the Reasoning Agent's last batch atomically detects it is the fan-in winner.

> **Screenshot checkpoint 3:** Capture the full transition log. This is the primary evidence that the entire pipeline executed end-to-end.

---

## 9. Stage-by-Stage Validation

### Stage 1 — `preparing` (Preparation Agent)

```powershell
docker logs wafagent-preparation --since 10m 2>&1 |
    Select-String -Pattern "subscription_scoped|batch_created|completed"
```

**Expected log lines:**
```json
{"event":"preparation.handler.subscription_scoped","subscription_id":"...","resource_count":142,"tag_filtered":false}
{"event":"preparation.handler.batch_created","batch_index":0,"subscription_id":"...","resource_count":50}
{"event":"preparation.handler.batch_created","batch_index":1,"subscription_id":"...","resource_count":50}
{"event":"preparation.handler.batch_created","batch_index":2,"subscription_id":"...","resource_count":42}
{"event":"preparation.handler.completed","total_batches":3,"subscription_count":1}
```

> The `resource_count` field shows your actual Azure resource count — proof of real discovery, not mock data.

### Stage 2 — `extracting` (Extraction Agent)

```powershell
docker logs wafagent-extraction --since 10m 2>&1 |
    Select-String -Pattern "rg_fetched|batch_completed|reasoning_published"
```

**Expected log lines:**
```json
{"event":"extraction.handler.rg_fetched","requested":50,"returned":50}
{"event":"extraction.handler.batch_completed","resource_count":50}
{"event":"extraction.handler.reasoning_published","batch_index":0,"total_batches":3}
```

### Stage 3 — `reasoning` (Reasoning Agent)

```powershell
docker logs wafagent-reasoning --since 15m 2>&1 |
    Select-String -Pattern "resource_evaluated|findings_inserted|batch_complete|reporting_published"
```

**Expected log lines:**
```json
{"event":"reasoning.handler.resource_evaluated","findings_count":3}
{"event":"reasoning.handler.resource_evaluated","findings_count":1}
{"event":"reasoning.handler.resource_evaluated","findings_count":0}
{"event":"reasoning.handler.findings_inserted","count":47}
{"event":"reasoning.handler.batch_complete","is_last_batch":false}
{"event":"reasoning.handler.batch_complete","is_last_batch":true}
{"event":"reasoning.handler.reporting_published","total_findings":112}
```

> `resource_evaluated` with `findings_count:0` is correct — many resources pass all applicable rules. `is_last_batch:true` is the fan-in trigger that fires reporting.

### Stage 4 — `reporting` (Reporting Agent)

```powershell
docker logs wafagent-reporting --since 5m 2>&1 |
    Select-String -Pattern "aggregated|excel_generated|pdf_generated|uploaded|assessment_completed"
```

**Expected log lines:**
```json
{"event":"reporting.handler.aggregated","total_findings":112,"total_resources":142,"overall_compliance":72.4,"risk_score":34.1}
{"event":"reporting.handler.excel_generated","size_bytes":524288}
{"event":"reporting.handler.pdf_generated","size_bytes":204800}
{"event":"reporting.handler.uploaded","xlsx_path":"reports/00000000-0000-0000-0000-000000000001/<id>/report.xlsx","pdf_path":"reports/00000000-0000-0000-0000-000000000001/<id>/report.pdf"}
{"event":"reporting.handler.assessment_completed"}
```

---

## 10. Findings Validation

### 10.1 Retrieve all findings — all five WAF pillars

```powershell
$response = Invoke-RestMethod `
    -Uri "http://localhost:8000/v1/assessments/$assessmentId/findings?limit=100"

$findings = $response.items
Write-Host "Total findings returned: $($findings.Count)"
Write-Host "Has more pages:          $($response.pagination.has_more)"
Write-Host ""
Write-Host "By severity:"
$findings | Group-Object severity | Sort-Object Name |
    ForEach-Object { Write-Host "  $($_.Name.PadRight(15)) $($_.Count)" }
Write-Host ""
Write-Host "By pillar (all five WAF pillars should appear):"
$findings | Group-Object pillar | Sort-Object Name |
    ForEach-Object { Write-Host "  $($_.Name.PadRight(30)) $($_.Count)" }
```

**Expected (pillar breakdown shows all five pillars):**
```
By pillar:
  cost_optimization              14
  operational_excellence         18
  performance_efficiency         12
  reliability                    28
  security                       40
```

> If a pillar shows zero findings, either no applicable rules fired for that pillar (correct for some resource mixes) or the `pillar_filter` in step 7.1 excluded it.

### 10.2 Filter findings by pillar — Security pillar

```powershell
$secResponse = Invoke-RestMethod `
    -Uri "http://localhost:8000/v1/assessments/$assessmentId/findings?pillar=security&limit=50"

Write-Host "Security pillar findings: $($secResponse.items.Count)"
$secResponse.items | Select-Object rule_id, severity, title | Format-Table -AutoSize
```

### 10.3 Filter findings by pillar — Reliability pillar

```powershell
$relResponse = Invoke-RestMethod `
    -Uri "http://localhost:8000/v1/assessments/$assessmentId/findings?pillar=reliability&limit=50"

Write-Host "Reliability pillar findings: $($relResponse.items.Count)"
$relResponse.items | Select-Object rule_id, severity, title | Format-Table -AutoSize
```

### 10.4 Filter findings by pillar — Cost Optimization pillar

```powershell
$costResponse = Invoke-RestMethod `
    -Uri "http://localhost:8000/v1/assessments/$assessmentId/findings?pillar=cost_optimization&limit=50"

Write-Host "Cost Optimization findings: $($costResponse.items.Count)"
$costResponse.items | Select-Object rule_id, severity, title | Format-Table -AutoSize
```

### 10.5 Retrieve all findings paginated and inspect Storage Account misconfigurations

```powershell
# Paginate through all findings
$allFindings = @()
$cursor = $null
do {
    $url = "http://localhost:8000/v1/assessments/$assessmentId/findings?limit=100"
    if ($cursor) { $url += "&cursor=$cursor" }
    $page = Invoke-RestMethod -Uri $url
    $allFindings += $page.items
    $cursor = $page.pagination.next_cursor
} while ($page.pagination.has_more)

Write-Host "Total findings fetched: $($allFindings.Count)"

# Show Storage Account findings (deliberate violations from step 6.1)
$storageFindings = $allFindings | Where-Object { $_.resource_type -like "*storage*" }
Write-Host "Storage Account findings: $($storageFindings.Count)"
$storageFindings | ForEach-Object {
    Write-Host ""
    Write-Host "Title:           $($_.title)" -ForegroundColor Yellow
    Write-Host "Severity:        $($_.severity)"
    Write-Host "Rule ID:         $($_.rule_id)"
    Write-Host "WAF Codes:       $($_.waf_codes -join ', ')"
    Write-Host "Pillar:          $($_.pillar)"
    Write-Host "Evaluation type: $($_.evaluation_type)"
    Write-Host "Confidence:      $($_.confidence_score)"
    Write-Host "Evidence:        $($_.evidence | ConvertTo-Json -Compress)"
    Write-Host "Recommendation:  $($_.recommendation)"
    Write-Host "---"
}
```

**Expected (Storage Account Security findings):**
```
Storage Account findings: 3

Title:           Storage Account minimum TLS version is below 1.2
Severity:        high
Rule ID:         SEC-STOR-001
WAF Codes:       SE-03
Pillar:          security
Evaluation type: deterministic
Confidence:      1.0
Evidence:        {"result":"FAIL","actual_value":"TLS1_0","expected_value":"TLS1_2"}
Recommendation:  Set minimumTlsVersion to TLS1_2 to prevent protocol downgrade attacks.
---
Title:           Storage Account allows public blob access
Severity:        high
Rule ID:         SEC-STOR-002
WAF Codes:       SE-03
Pillar:          security
Evaluation type: deterministic
Confidence:      1.0
Evidence:        {"result":"FAIL","actual_value":true,"expected_value":false}
Recommendation:  Set allowBlobPublicAccess to false to prevent unintended data exposure.
---
Title:           Storage Account does not enforce HTTPS-only traffic
Severity:        medium
Rule ID:         SEC-STOR-003
WAF Codes:       SE-03, SE-04
Pillar:          security
Evaluation type: deterministic
Confidence:      1.0
Evidence:        {"result":"FAIL","actual_value":false,"expected_value":true}
Recommendation:  Enable enableHttpsTrafficOnly to prevent unencrypted data in transit.
```

> **Screenshot checkpoint 4:** Capture these three findings. The `evidence` JSON field (`"actual_value":"TLS1_0"`) proves the platform read an actual Azure Resource Graph property and compared it against the WAF rule's expected value — not a mock.

---

## 11. Cross-Pillar Finding Examples

This section shows representative findings across all five WAF pillars. Exact findings depend on your subscription's resource configuration.

### 11.1 Security — Key Vault not using soft-delete

```powershell
$kvFindings = $allFindings | Where-Object { $_.rule_id -like "SEC-KV-*" }
$kvFindings | Select-Object rule_id, severity, title, recommendation | Format-List
```

### 11.2 Reliability — VM without availability zone redundancy

```powershell
$relVmFindings = $allFindings | Where-Object { $_.rule_id -like "REL-VM-*" }
$relVmFindings | Select-Object rule_id, severity, title, recommendation | Format-List
```

### 11.3 Operational Excellence — Resource missing diagnostic settings

```powershell
$opsFindings = $allFindings | Where-Object { $_.rule_id -like "OPS-DIAG-*" -or $_.rule_id -like "OPS-MON-*" }
$opsFindings | Select-Object rule_id, severity, title, recommendation | Format-List
```

### 11.4 Performance Efficiency — VM using non-Premium disk for production

```powershell
$perfFindings = $allFindings | Where-Object { $_.pillar -eq "performance_efficiency" }
$perfFindings | Select-Object rule_id, severity, title | Format-Table -AutoSize
```

### 11.5 Cost Optimization — Unattached managed disk incurring cost

```powershell
$costFindings = $allFindings | Where-Object { $_.rule_id -like "CST-DISK-*" -or $_.rule_id -like "CST-IP-*" }
$costFindings | Select-Object rule_id, severity, title, recommendation | Format-List
```

---

## 12. WAF Traceability Validation

Each finding carries `waf_codes`, `waf_titles`, and `microsoft_urls` populated by the WAF Catalog singleton at reasoning time.

### 12.1 Inspect a finding's full traceability chain

```powershell
$finding = $allFindings | Where-Object { $_.rule_id -eq "SEC-STOR-001" } | Select-Object -First 1

Write-Host "Finding → Rule → WAF Control → Microsoft Docs"
Write-Host ""
Write-Host "Finding Title:  $($finding.title)"
Write-Host "Resource ID:    $($finding.resource_id)"
Write-Host "Rule ID:        $($finding.rule_id)"
Write-Host ""
for ($i = 0; $i -lt $finding.waf_codes.Count; $i++) {
    Write-Host "WAF Code:       $($finding.waf_codes[$i])"
    Write-Host "WAF Title:      $($finding.waf_titles[$i])"
    Write-Host "Pillar:         $($finding.pillar)"
    Write-Host "Microsoft URL:  $($finding.microsoft_urls[$i])"
    Write-Host ""
}
```

**Expected output:**
```
Finding → Rule → WAF Control → Microsoft Docs

Finding Title:  Storage Account minimum TLS version is below 1.2
Resource ID:    /subscriptions/.../storageAccounts/stwafweak1234
Rule ID:        SEC-STOR-001

WAF Code:       SE-03
WAF Title:      Encrypt data at rest and in transit
Pillar:         security
Microsoft URL:  https://learn.microsoft.com/azure/well-architected/security/...
```

### 12.2 Verify catalog coverage across all findings

The WAF Catalog maps 87 rule IDs to WAF control codes. Check coverage across all findings:

```powershell
$mapped   = $allFindings | Where-Object { $_.waf_codes.Count -gt 0 }
$unmapped = $allFindings | Where-Object { $_.waf_codes.Count -eq 0 }
Write-Host "Total findings:      $($allFindings.Count)"
Write-Host "Mapped to WAF codes: $($mapped.Count)"
Write-Host "Not yet mapped:      $($unmapped.Count)"
if ($allFindings.Count -gt 0) {
    Write-Host "Mapping coverage:    $('{0:P1}' -f ($mapped.Count / $allFindings.Count))"
}
```

---

## 13. Human Review Validation

Four WAF controls require human attestation and cannot be objectively assessed via Azure APIs:

| Control | Pillar | Reason |
|---|---|---|
| SE-10 | Security | Adversarial testing (penetration testing) — no Azure API provides results |
| OE-03 | Operational Excellence | Software planning management — requires interview evidence |
| OE-04 | Operational Excellence | Continuous integration maturity — requires pipeline evidence |
| CO-09 | Cost Optimization | Personnel time optimization — requires workforce data |

### 13.1 List the human review controls and their questionnaires

```powershell
$controls = Invoke-RestMethod -Uri "http://localhost:8000/v1/human-review/controls"
$controls | ForEach-Object {
    Write-Host ""
    Write-Host "Code:    $($_.code)" -ForegroundColor Yellow
    Write-Host "Pillar:  $($_.pillar)"
    Write-Host "Title:   $($_.title)"
    Write-Host "Questions ($($_.questions.Count)):"
    $_.questions | ForEach-Object { Write-Host "  - [$($_.id)] $($_.text)" }
}
```

### 13.2 Submit a human review for SE-10 (Security — Adversarial Testing)

```powershell
$reviewBody = @{
    control_code      = "SE-10"
    compliance_status = "partially_compliant"
    score             = 65
    answers           = @(
        @{
            question_id = "se10_q1"
            answer      = "quarterly"
            notes       = "External pen-test via third-party firm, last completed Q1 2026"
        }
    )
    evidence_refs     = @(
        @{
            evidence_type   = "pdf"
            url_or_filename = "pentest-report-q1-2026.pdf"
            description     = "External penetration test report — Q1 2026"
        }
    )
    comments          = "Penetration testing conducted quarterly by CrowdStrike. Latest report attached."
} | ConvertTo-Json -Depth 5

$review = Invoke-RestMethod `
    -Method POST `
    -Uri "http://localhost:8000/v1/human-review/assessments/$assessmentId/reviews" `
    -Headers @{ "Content-Type" = "application/json" } `
    -Body $reviewBody

Write-Host "Review ID:    $($review.id)"
Write-Host "Control:      $($review.control_code)"
Write-Host "Status:       $($review.status)"
Write-Host "Compliance:   $($review.compliance_status)"
Write-Host "Score:        $($review.score)"
```

**Expected (HTTP 201 Created):**
```
Review ID:    xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Control:      SE-10
Status:       completed
Compliance:   partially_compliant
Score:        65
```

### 13.3 Submit a human review for OE-03 (Operational Excellence — Software Planning)

```powershell
$oe03Body = @{
    control_code      = "OE-03"
    compliance_status = "compliant"
    score             = 82
    answers           = @(
        @{
            question_id = "oe03_q1"
            answer      = "yes"
            notes       = "Jira used for sprint planning with documented velocity tracking"
        }
    )
    evidence_refs     = @()
    comments          = "Two-week sprints, quarterly roadmap planning, documented in Confluence."
} | ConvertTo-Json -Depth 5

Invoke-RestMethod `
    -Method POST `
    -Uri "http://localhost:8000/v1/human-review/assessments/$assessmentId/reviews" `
    -Headers @{ "Content-Type" = "application/json" } `
    -Body $oe03Body | Select-Object control_code, compliance_status, score
```

### 13.4 Retrieve the human review summary for the assessment

```powershell
$summary = Invoke-RestMethod `
    -Uri "http://localhost:8000/v1/human-review/assessments/$assessmentId/summary"

Write-Host "Automated controls covered: $($summary.automated_controls_covered) / $($summary.automated_controls_total)"
Write-Host "Automated coverage:         $($summary.automated_coverage_percentage)%"
Write-Host ""
Write-Host "Human review total:         $($summary.human_review_total)"
Write-Host "Human review completed:     $($summary.human_review_completed)"
Write-Host "Human review compliant:     $($summary.human_review_compliant)"
Write-Host "Human review pending:       $($summary.human_review_pending)"
Write-Host ""
Write-Host "Total framework coverage:   $($summary.total_framework_coverage_percentage)%"
Write-Host "Total controls:             $($summary.total_controls)"
```

---

## 14. Report Validation

### 14.1 Retrieve report metadata

```powershell
$report = Invoke-RestMethod `
    -Uri "http://localhost:8000/v1/assessments/$assessmentId/report"

Write-Host "Report ID:        $($report.id)"
Write-Host "Generated at:     $($report.generated_at)"
Write-Host "Excel blob path:  $($report.xlsx_blob_path)"
Write-Host "PDF blob path:    $($report.pdf_blob_path)"
Write-Host ""
Write-Host "Summary:"
Write-Host "  Total resources:   $($report.summary.total_resources)"
Write-Host "  Total findings:    $($report.summary.total_findings)"
Write-Host "  Coverage:          $($report.summary.coverage_percentage)%"
Write-Host ""
Write-Host "Findings by severity:"
$report.summary.findings_by_severity.PSObject.Properties |
    ForEach-Object { Write-Host "  $($_.Name.PadRight(15)) $($_.Value)" }
Write-Host ""
Write-Host "Findings by pillar:"
$report.summary.findings_by_pillar.PSObject.Properties |
    ForEach-Object { Write-Host "  $($_.Name.PadRight(30)) $($_.Value)" }
```

**Expected:**
```
Report ID:        xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Generated at:     2026-06-25T14:33:48.000Z
Excel blob path:  reports/00000000-0000-0000-0000-000000000001/<assessment_id>/report.xlsx
PDF blob path:    reports/00000000-0000-0000-0000-000000000001/<assessment_id>/report.pdf

Summary:
  Total resources:   142
  Total findings:    112
  Coverage:          78.9%

Findings by severity:
  critical         8
  high             23
  medium           41
  low              30
  informational    10

Findings by pillar:
  cost_optimization              14
  operational_excellence         18
  performance_efficiency         12
  reliability                    28
  security                       40
```

> **Screenshot checkpoint 5:** Capture the report metadata API response. The blob paths prove where reports were uploaded.

### 14.2 Download both reports from Azure Blob Storage

```powershell
$storageAccount = (Get-Content .env | Select-String "^STORAGE_ACCOUNT_NAME=").ToString().Split("=")[1].Trim()
$dateStamp      = Get-Date -Format 'yyyyMMdd'

az storage blob download `
    --account-name $storageAccount `
    --container-name "reports" `
    --name $report.xlsx_blob_path `
    --file "WAF-Report-$dateStamp.xlsx" `
    --auth-mode login

az storage blob download `
    --account-name $storageAccount `
    --container-name "reports" `
    --name $report.pdf_blob_path `
    --file "WAF-Report-$dateStamp.pdf" `
    --auth-mode login

Start-Process "WAF-Report-$dateStamp.xlsx"
```

**If blob upload failed and reports are stored locally** (degraded path — see troubleshooting):

```powershell
docker cp wafagent-reporting:/tmp/reports/d6925c98-90ba-4a1b-9a41-0f29ae98efa3/report.xlsx "WAF-Report-$dateStamp.xlsx"
docker cp wafagent-reporting:/tmp/reports/d6925c98-90ba-4a1b-9a41-0f29ae98efa3/report.pdf  "WAF-Report-$dateStamp.pdf"
```

---

## 15. Report Walkthrough — Every Section Explained

The enterprise report is the deliverable. This section walks through every sheet of the Excel workbook and every section of the PDF in presentation order. Use this script when opening the report with a manager or evaluator.

---

### Excel Workbook — 29 Sheets

#### Sheet 1 — Executive Summary

**Purpose:** The at-a-glance executive page. Contains the risk rating, key findings, top-5 prioritised remediation actions, a 30/60/90-day compliance projection, and a one-paragraph management summary narrative.

**Data source:** `assessment_findings` aggregated by severity and pillar; compliance projection derived from finding severity distribution.

**Inputs:** All findings across all pillars.

**Calculations:**
- Risk rating (Critical/High/Medium/Low) derived from weighted severity score
- Top-5 remediation actions ordered by severity weight × resource criticality
- Compliance projection assumes median remediation rate from historical trend data

**Business value:** One page that a non-technical executive can read in 60 seconds to understand the overall posture and the three most important actions.

**Presentation:** Open this sheet first. Say: "This is the one-page summary. The risk rating at the top is derived from a weighted formula that accounts for severity and resource criticality. The three top actions here are the highest-impact remediations."

---

#### Sheet 2 — Executive Dashboard

**Purpose:** Numeric summary of the four enterprise scores (Overall Compliance, Overall Risk, Weighted Severity, Business Impact), plus the Top-5 risk table.

**Data source:** `scoring.py` `ScoringResult`; `aggregator.py` `top_5_risks`.

**Scoring formulas:**

| Score | Formula |
|---|---|
| Overall Compliance | `Σ(pillar_score × pillar_weight)` where pillar weights are Security 30%, Reliability 20%, Performance Efficiency 20%, Operational Excellence 15%, Cost Optimization 15% |
| Pillar Score | `weighted_passed / weighted_applicable × 100`; weight = `severity_weight × resource_criticality` |
| Overall Risk | `min(100, (100 − compliance) + (critical+high) / total_findings × 10)` |
| Weighted Severity | `Σ(severity_weight × count) / (total × max_severity_weight) × 100` |
| Business Impact | Pillar-risk weighted by pillar importance and finding volume |

**Severity weights:** Critical=10, High=7, Medium=5, Low=2, Informational=1

**Presentation:** "These four numbers are deterministic — the same findings always produce the same scores. An Overall Compliance of 72 means 72% of the weighted checks passed. Risk of 34 means there is meaningful active risk. The Top-5 table shows which specific resource violations are driving the most risk."

---

#### Sheet 3 — Visual Dashboard

**Purpose:** A visual-first summary with KPIs, a risk heatmap, pillar compliance bars, severity distribution, and a clickable table of contents linking to all other sheets.

**Data source:** `build_dashboard_data()` in `services/dashboard_builder.py`.

**Presentation:** Use this sheet during the live demo to orient the audience visually before opening detailed sheets.

---

#### Sheet 4 — Architecture Diagram

**Purpose:** Hierarchical grid of resources organised by subscription → resource group → resource type. Color-coded by compliance health. Each cell shows resource count and compliance percentage.

**Data source:** `architecture_diagram.py` `hierarchy_rows()`; derived from `assessment_resources`.

**Color coding:** Green = no findings. Orange = <50% of resources affected. Red = ≥50% affected.

**Presentation:** "This is every resource type in your environment, arranged by resource group. Red boxes are the areas most in need of remediation."

---

#### Sheet 5 — Resource Inventory

**Purpose:** Per-resource-type compliance table. Shows total resources, compliant count, non-compliant count, compliance percentage, and critical/high finding counts for every resource type found.

**Data source:** `assessment_resources` LEFT JOIN `assessment_findings` grouped by resource type.

**Presentation:** "Every row is a resource type. The percentage column is your compliance score for that type. Click any red row to understand the exposure."

---

#### Sheet 6 — Pillar Scorecard

**Purpose:** Side-by-side compliance scores for all five pillars, with WAF benchmark targets. Shows which pillars are above/below the Microsoft-recommended targets.

**WAF benchmark targets:**

| Pillar | Target | Rationale |
|---|---|---|
| Security | 90% | Enterprise minimum for SOC 2 / ISO 27001 |
| Reliability | 85% | Aligns with 99.9% availability SLA |
| Operational Excellence | 85% | ITIL and DevOps maturity baseline |
| Cost Optimization | 80% | Headroom for workload-specific spend decisions |
| Performance Efficiency | 80% | Solid baseline without over-engineering |

**Presentation:** "Green bars are above target. Red bars show gap to Microsoft's recommended threshold. Security needs to reach 90% to satisfy enterprise compliance requirements."

---

#### Sheets 7–11 — Pillar Findings (Security, Reliability, Operational Excellence, Performance Efficiency, Cost Optimization)

**Purpose:** One sheet per pillar — all findings for that pillar, color-coded by severity (Critical=red, High=orange, Medium=yellow, Low=blue, Informational=grey).

**Data source:** `assessment_findings` filtered by pillar.

**Columns:** Finding ID, Rule ID, Resource ID, Resource Type, Pillar, Severity, Status, Title, Recommendation, WAF Codes, Microsoft URLs, Confidence, Created At, Evidence Snapshot.

**Presentation for Security sheet:** "Use Excel's filter on the Severity column. Select Critical. These are the findings that require immediate action — no waiting for the next sprint."

**Presentation for Cost Optimization sheet:** "These are findings that are directly wasting money. Unattached disks, idle IPs, and oversized VMs show up here with specific remediation steps."

---

#### Sheet 12 — Business Impact

**Purpose:** Maps every finding to a business impact category, showing the business consequence of each pillar's failures.

**Impact mapping:**

| Pillar | Business Impact Category |
|---|---|
| security | Security Exposure |
| reliability | Availability Risk |
| cost_optimization | Financial Waste |
| operational_excellence | Operational Risk |
| performance_efficiency | Performance Degradation |

**Presentation:** "Point to the 'Availability Risk' row — those are Reliability failures that could cause downtime. Point to 'Financial Waste' — those are Cost Optimization failures that are measurably costing money right now."

---

#### Sheet 13 — AI Executive Insights

**Purpose:** Gemini-generated strategic insights derived from the finding patterns. Produces 3–5 prioritised insights with confidence scores, each linking back to supporting evidence.

**Data source:** `executive_insights.py` `generate_executive_insights()`.

**Presentation:** "These insights are generated by Gemini from the actual finding patterns. Notice it identifies cross-pillar themes — for example, 'lack of monitoring across multiple resource types is simultaneously a Reliability, Operational Excellence, and Performance risk.'"

---

#### Sheet 14 — Traceability Matrix

**Purpose:** Every finding traced to its WAF control, rule ID, pillar, and Microsoft documentation URL. One row per WAF code per finding.

**Columns:** Finding Title, Resource ID, Rule ID, WAF Code, Pillar, Severity, Remediation, Microsoft URL (clickable hyperlink).

**Presentation:** "Pick any row. Click the Microsoft URL. It links to the exact WAF control documentation that this finding is derived from. Every finding is grounded in published Microsoft standards — not internal checklists."

---

#### Sheet 15 — Human Reviews

**Purpose:** Compliance status and scores for the four human-review controls: SE-10, OE-03, OE-04, CO-09. Shows reviewer, compliance verdict, score (0–100), submitted answers, and evidence references.

**Data source:** `human_review_assessments` table via `HumanReviewRepository`.

**Presentation:** "These four controls cannot be evaluated by an API — they require human attestation. The reviewer submitted structured answers and attached evidence. The score and compliance verdict are recorded here and flow into the overall framework coverage percentage."

---

#### Sheet 16 — Trend Analysis

**Purpose:** Historical compliance trajectory across previous assessments for the same tenant (up to 6 prior assessments). Shows compliance score progression over time.

**Data source:** `assessment_reports.summary` from prior assessments (excluding the current one).

**If this is the first assessment:** Sheet displays "Trend analysis not yet available. Complete additional assessments to populate trend data."

**Presentation:** "After the second assessment, this sheet will show whether compliance is improving. Organizations running this monthly use it as the executive KPI."

---

#### Sheet 17 — Grouped Findings

**Purpose:** Findings deduplicated and grouped by rule ID. One row per (rule_id, severity, recommendation) group, with affected resources listed. Useful for prioritising remediations that fix many resources with one action.

**Presentation:** "A single rule violation affecting 30 resources appears as one row here. Fix the policy once; all 30 resources become compliant."

---

#### Sheets 18–21 — Remediation Sheets

| Sheet | Content |
|---|---|
| Remediation Detail | Detailed fix instructions per finding, with Azure CLI commands and portal steps |
| Remediation Roadmap | 30/60/90-day prioritised remediation plan by effort and impact |
| Remediation Playbooks | Step-by-step runbooks for the highest-impact finding types |
| Implementation Roadmap | Enterprise roadmap: quick wins → medium-term → strategic improvements |

**Presentation:** "Sheet 19 gives your engineering team a week-by-week plan. Sheet 20 gives them runbooks with specific Azure CLI commands. These come out of the box with every assessment."

---

#### Sheet 22 — All Findings

**Purpose:** Complete flat table of every finding across all pillars and severities. Sortable and filterable. Used as the source for ticket creation.

**Columns:** Same as pillar sheets. Every finding, no filtering.

**Presentation:** "Export this sheet to Excel, paste into your ITSM tool, or import it into Jira. Every row is a ticket-ready finding."

---

#### Sheets 23–29 — Reference and Methodology Sheets

| Sheet | Content |
|---|---|
| Coverage Report | Per-WAF-control coverage status — which controls have findings, which were assessed, which are not yet covered |
| Gap Analysis | Controls with no findings and assessment gaps — what the platform does not yet cover |
| Compliance Mapping | ISO 27001, NIST CSF, and CIS benchmark control cross-references |
| Risk Matrix | 5×5 severity/likelihood risk matrix with findings plotted |
| Audit Trail | Timestamp, status, and actor log for the assessment lifecycle |
| Glossary | Definitions for WAF terms, severity levels, and pillar names |
| Methodology | Full scoring methodology documentation for auditors |

---

### PDF Report — 33 Sections

The PDF is a standalone executive document. Print-ready, no spreadsheet required.

| Section | Title | Purpose |
|---|---|---|
| 1 | Cover Page | Assessment ID, tenant, generation timestamp, classification |
| 2 | Executive Risk Statement | AI-generated narrative risk summary; overall posture in prose |
| 3 | Executive Summary | Risk rating, key risks, top-5 actions, compliance projection, management summary |
| 4 | Pillar Scorecard | All-pillar bar chart with benchmark targets |
| 5 | Security Scorecard | 5-category heat-bar scorecard: Identity & Access, Data Protection, Network Security, Operational Security, Governance |
| 6 | Executive Dashboard | Four enterprise scores + Top-5 risk table |
| 7 | Visual Dashboards | KPI grid, severity donut, pillar radar chart, risk heatmap |
| 8 | Resource Inventory | Per-resource-type table + compliance bar chart |
| 9 | Resource Group Breakdown | Compliance per resource group + bar chart |
| 10 | Compliance Overview | All-pillar compliance table + bar chart |
| 11 | WAF Benchmark | Current scores vs. Microsoft-recommended targets per pillar |
| 12 | Business Impact | Impact category analysis + distribution chart |
| 13 | Executive Insights | 3–5 AI-generated strategic insights with confidence scores |
| 14 | Architecture Topology | Hierarchy diagram: subscription → resource group → resource type |
| 15 | WAF Control Pages | One page per WAF control referenced by findings |
| 16 | Trend Analysis | Historical compliance trajectory (or "Not Yet Available") |
| 17 | Compliance Roadmap | Score trajectory projection with remediation milestones |
| 18 | Executive Remediation Roadmap | Priority-ordered top-20 remediations for executive review |
| 19 | Remediation Roadmap | Detailed remediation steps ordered by priority |
| 20 | Remediation Playbooks | Step-by-step runbooks for high-impact finding types |
| 21 | Enterprise Remediation Roadmap | 30/60/90-day phased implementation plan |
| 22 | Human Review Results | SE-10, OE-03, OE-04, CO-09 review verdicts and scores |
| 23 | WAF Traceability Matrix | Finding → Rule → WAF Code → Microsoft URL (capped at 200 rows; full data in Excel Sheet 14) |
| 24 | Detailed Findings | Per-pillar finding tables with evidence and recommendations |
| 25 | Executive Recommendations | Top-5 AI-generated strategic recommendations |
| 26 | Appendix | Full findings table, scoring methodology summary |
| 27 | Compliance Framework Mapping | ISO 27001, NIST CSF, CIS control cross-references |
| 28 | Risk Matrix | 5×5 severity/likelihood matrix with findings plotted |
| 29 | Assessment Methodology | Full scoring methodology explanation for auditors |
| 30 | Confidence Explanation | How deterministic vs. LLM confidence scores are calculated |
| 31 | Limitations | What the platform does not assess and known limitations |
| 32 | Audit Trail | Assessment lifecycle event log |
| 33 | Glossary | Definitions for WAF terminology |

---

## 16. Blob Storage Validation

```powershell
$storageAccount = (Get-Content .env | Select-String "^STORAGE_ACCOUNT_NAME=").ToString().Split("=")[1].Trim()
$blobPrefix = $report.xlsx_blob_path -replace '/[^/]+$', ''

az storage blob list `
    --account-name $storageAccount `
    --container-name "reports" `
    --prefix $blobPrefix `
    --auth-mode login `
    --query "[].{name:name, size:properties.contentLength, lastModified:properties.lastModified}" `
    -o table
```

**Expected output:**
```
Name                                                                                   Size     LastModified
-------------------------------------------------------------------------------------  -------  ------------------------
reports/00000000-0000-0000-0000-000000000001/<assessment_id>/report.xlsx               524288   2026-06-25T14:33:47+00:00
reports/00000000-0000-0000-0000-000000000001/<assessment_id>/report.pdf                204800   2026-06-25T14:33:48+00:00
```

> **Screenshot checkpoint 6:** Capture the blob listing. Two files exist at `reports/{tenant_id}/{assessment_id}/`. This proves the Reporting Agent uploaded to Azure Blob Storage using Managed Identity — not a local filesystem fallback path.

---

## 17. Manager Demo Script (8–10 Minutes)

Run steps 6–16 in advance. Reports will already exist. During the meeting, run steps marked **[LIVE]** and show pre-captured screenshots for the time-consuming stages.

> **Session prerequisite:** All [LIVE] commands depend on PowerShell variables set in steps 7–14 (`$assessmentId`, `$allFindings`, `$report`). Run this entire demo in a **single PowerShell session**. If the session was closed, re-run steps 7.1, 10.5, and 14.1 to restore these variables before the meeting. Step 7.1 will create and process a fresh assessment — allow 30–45 minutes for it to complete before the meeting starts.

---

### [0:00] The business problem (45 seconds)

> "Manual Azure Well-Architected Framework reviews take two to three days per subscription — and that is just for Security. To cover all five pillars — Security, Reliability, Operational Excellence, Performance Efficiency, and Cost Optimization — a consultant needs a full week per subscription.
>
> The output is a Word document that is accurate for one day before Azure resources change. It is expensive, inconsistent, and impossible to run at scale.
>
> This platform eliminates the manual work. It connects directly to your Azure subscription, discovers every resource automatically, evaluates each one against 87 WAF rules across all five pillars, and delivers a structured, downloadable report in under 45 minutes."

---

### [0:45] Architecture overview (45 seconds)

> "Four agents on a Service Bus pipeline: Preparation discovers resources via Azure Resource Graph, Extraction fetches full ARM property sets, Reasoning evaluates WAF rules using both deterministic logic and Gemini AI, and Reporting generates the 29-sheet Excel workbook and 33-section PDF.
>
> Every piece of data in the report is traceable to a specific database record, which is traceable to a specific Azure resource property read from the Azure Resource Graph API. Nothing is fabricated."

*(Show the Docker Desktop dashboard or run `docker compose -f docker-compose.dev.yml --profile full ps`.)*

---

### [1:30] Live assessment creation **[LIVE]**

```powershell
$liveBody = @{
    idempotency_key  = "demo-live-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    subscription_ids = @($subscriptionId)
    pillar_filter    = @(
        "Security", "Reliability", "Operational Excellence",
        "Performance Efficiency", "Cost Optimization"
    )
    tag_filter = $null
} | ConvertTo-Json

$liveAssessment = Invoke-RestMethod `
    -Method POST `
    -Uri "http://localhost:8000/v1/assessments" `
    -Headers @{ "Content-Type" = "application/json" } `
    -Body $liveBody

Write-Host "Assessment ID: $($liveAssessment.id)"
Write-Host "Status:        $($liveAssessment.status)"
```

> "Status is `pending`. The API published an `assessment.created` event to Service Bus in real time. The Preparation Agent is now querying Azure Resource Graph for all resource types in your subscription..."

```powershell
Start-Sleep -Seconds 10
$current = Invoke-RestMethod -Uri "http://localhost:8000/v1/assessments/$($liveAssessment.id)"
Write-Host "Status:        $($current.status)"
Write-Host "Total batches: $($current.total_batches)"
```

> "It moved to `preparing` — it found resources in your subscription and created processing batches. While this runs in the background, let me show you what a completed assessment produces."

---

### [2:15] All five pillars in the findings **[using pre-completed assessment]**

```powershell
Write-Host "Findings across all five WAF pillars:"
$allFindings | Group-Object pillar | Sort-Object Name |
    ForEach-Object { Write-Host "  $($_.Name.PadRight(30)) $($_.Count) findings" }
```

> "Every WAF pillar is represented. This is not a Security-only tool. Cost Optimization findings identify resources that are actively wasting money. Reliability findings identify single points of failure. Operational Excellence findings identify missing monitoring and governance gaps."

---

### [3:00] A real Security finding **[using pre-completed assessment]**

```powershell
$secFinding = $allFindings | Where-Object { $_.rule_id -eq "SEC-STOR-001" } | Select-Object -First 1
Write-Host "Title:          $($secFinding.title)"
Write-Host "Severity:       $($secFinding.severity)"
Write-Host "Evidence:       $($secFinding.evidence | ConvertTo-Json -Compress)"
Write-Host "Recommendation: $($secFinding.recommendation)"
Write-Host "WAF Code:       $($secFinding.waf_codes -join ', ')"
```

> "The Storage Account `stwafweak1234` was configured with TLS 1.0. The platform read the Azure Resource Graph property `minimumTlsVersion: TLS1_0`, evaluated it against rule SEC-STOR-001, and produced this finding with exact evidence. The WAF code SE-03 links this to Microsoft's published encryption-in-transit standard."

---

### [4:00] A real Cost Optimization finding

```powershell
$costFinding = $allFindings |
    Where-Object { $_.pillar -eq "cost_optimization" -and $_.severity -in @("high","medium") } |
    Select-Object -First 1
if ($costFinding) {
    Write-Host "Rule ID:        $($costFinding.rule_id)"
    Write-Host "Title:          $($costFinding.title)"
    Write-Host "Severity:       $($costFinding.severity)"
    Write-Host "Recommendation: $($costFinding.recommendation)"
}
```

> "This is a Cost Optimization finding — a resource configuration that is measurably wasting money. Every pillar produces the same structured output: finding, evidence, WAF code, remediation step."

---

### [5:00] Report demonstration

```powershell
Write-Host "Report summary:"
Write-Host "  Total resources: $($report.summary.total_resources)"
Write-Host "  Total findings:  $($report.summary.total_findings)"
Write-Host "  Coverage:        $($report.summary.coverage_percentage)%"
```

*(Open pre-downloaded Excel file.)*

> "The Excel workbook has 29 sheets. Let me show you the most important ones.
>
> Sheet 1 is the Executive Summary — risk rating, top-5 actions, 90-day compliance projection.
>
> Sheet 6 is the Pillar Scorecard — all five pillars scored against Microsoft's benchmark targets. Security needs to reach 90% for SOC 2 compliance. You can see the current score and the gap.
>
> Sheet 14 is the WAF Traceability Matrix — every finding traced to a specific Microsoft WAF control code with a link to Microsoft's documentation. This is what auditors ask for.
>
> Sheet 22 is the full findings table — sortable, filterable, ready to paste into Jira."

---

### [6:30] Scoring explanation

> "Every score is deterministic. Overall Compliance uses a weighted pass-rate formula. Security has a 30% weight in the overall score — Microsoft's own WAF guidance gives it the largest share. A critical finding on a Key Vault reduces the score more than the same finding on a managed disk, because Key Vault has a 1.5× resource criticality multiplier in the engine.
>
> These weights are configurable per tenant. They are not magic numbers — every parameter is documented in the Methodology sheet."

---

### [7:15] Blob Storage proof

*(Show screenshot checkpoint 6.)*

> "Both files are in Azure Blob Storage at `{storage-account}/reports/{tenant}/{assessment-id}/`. Uploaded using Managed Identity — no storage account keys in the code, no SAS tokens stored in the database. The API tier generates 15-minute SAS tokens on demand for downloads."

---

### [8:00] Human Review integration

```powershell
$hrSummary = Invoke-RestMethod `
    -Uri "http://localhost:8000/v1/human-review/assessments/$assessmentId/summary"
Write-Host "Automated controls:       $($hrSummary.automated_controls_covered) covered"
Write-Host "Human review completed:   $($hrSummary.human_review_completed) of $($hrSummary.human_review_total)"
Write-Host "Total framework coverage: $($hrSummary.total_framework_coverage_percentage)%"
```

> "Four controls — adversarial testing, software planning, CI maturity, and personnel cost — cannot be evaluated by an API. A reviewer submits structured answers and attaches evidence files. Those responses flow into the Human Reviews sheet and count toward the overall framework coverage percentage."

---

### [8:45] Scale close

> "At ten subscriptions, monthly cadence, this replaces over 200 hours of consultant time per year. The findings are consistent, auditable, and traceable to Microsoft's published WAF standards.
>
> The platform evaluates all five WAF pillars — Security gets the most attention in practice, but Cost Optimization and Reliability findings are where organisations find the fastest wins: eliminating idle resources and adding availability zone redundancy.
>
> The next version adds Azure Policy integration and automated remediation playbooks."

---

## 18. Evidence Collection Checklist

Capture all screenshots before the manager meeting. Label each file with the checkpoint number.

| # | Filename | Content | Where |
|---|---|---|---|
| 01 | `cp01-weak-storage.png` | `az storage account show` output: TLS1_0, public access True, HTTPS False | Step 6.1 |
| 02 | `cp02-healthz.png` | `GET /healthz` → `{"status":"ok"}` | Step 4.4 |
| 03 | `cp03-readyz.png` | `GET /readyz` → `{"status":"ok","checks":{"database":"ok","redis":"ok"}}` | Step 4.5 |
| 04 | `cp04-containers.png` | `docker compose ps` — all containers running/healthy, migrate and healthtools Exited(0) | Step 5.2 |
| 05 | `cp05-assessment-created.png` | `POST /v1/assessments` 202 response with UUID and `"status":"pending"` | Step 7.1 |
| 06 | `cp06-lifecycle.png` | Full polling loop output — every status transition with timestamps | Step 8 |
| 07 | `cp07-preparation-logs.png` | `subscription_scoped` log line with `resource_count` ≥ 1 | Step 9 Stage 1 |
| 08 | `cp08-reporting-logs.png` | `excel_generated`, `pdf_generated`, `uploaded` log lines with file sizes | Step 9 Stage 4 |
| 09 | `cp09-findings-by-pillar.png` | All five pillars showing findings counts | Step 10.1 |
| 10 | `cp10-storage-findings.png` | Three Storage Account findings with `rule_id`, `evidence` JSON, `waf_codes` | Step 10.5 |
| 11 | `cp11-traceability.png` | Full traceability chain: finding → rule → WAF code → Microsoft URL | Step 12.1 |
| 12 | `cp12-human-review.png` | SE-10 review 201 response with `compliance_status` and `score` | Step 13.2 |
| 13 | `cp13-report-metadata.png` | `GET /report` response showing `xlsx_blob_path` and `pdf_blob_path` | Step 14.1 |
| 14 | `cp14-blob-list.png` | `az storage blob list` showing `report.xlsx` and `report.pdf` with sizes | Step 16 |
| 15 | `cp15-excel-summary.png` | Excel Sheet 1 — Executive Summary with risk rating and top-5 actions | Step 14.2 |
| 16 | `cp16-excel-scorecard.png` | Excel Sheet 6 — Pillar Scorecard with all five pillars vs. benchmark targets | Step 14.2 |
| 17 | `cp17-excel-security.png` | Excel Sheet 7 (Security) — Storage Account rows with CRITICAL/HIGH severity highlighted | Step 14.2 |
| 18 | `cp18-excel-cost.png` | Excel Sheet 11 (Cost Optimization) — showing financial waste findings | Step 14.2 |
| 19 | `cp19-excel-traceability.png` | Excel Sheet 14 — WAF Traceability Matrix with Microsoft URLs as hyperlinks | Step 14.2 |
| 20 | `cp20-pdf-cover.png` | PDF cover page showing assessment ID and timestamp | Step 14.2 |

**Minimum viable evidence pack:** checkpoints 04, 06, 09, 10, 13, 15, 16, 19.

---

## 19. Troubleshooting

### Stage: `pending` — assessment stuck, no transition to `preparing`

**Symptom:** `GET /v1/assessments/{id}` returns `"status":"pending"` for more than 30 seconds.

**Diagnosis:**
```powershell
docker logs wafagent-api --since 2m 2>&1 | Select-String "assessment.created|servicebus|ERROR"
docker logs wafagent-preparation --since 2m 2>&1 | Select-String "received|ERROR"
docker inspect wafagent-servicebus --format '{{.State.Health.Status}}'
```

| Symptom | Cause | Fix |
|---|---|---|
| No `received` log in preparation agent | Service Bus message not delivered | Check `SERVICEBUS_CONNECTION_STRING` in container env: `docker inspect wafagent-preparation --format '{{range .Config.Env}}{{println .}}{{end}}' | Select-String SERVICEBUS` |
| `wafagent-servicebus` is `unhealthy` | SQL Edge not ready when emulator started | `docker compose -f docker-compose.dev.yml restart servicebus-emulator` |
| API returns 401 on POST | `API_AUTH_MODE` not set to `development` | Verify: `docker inspect wafagent-api --format '{{range .Config.Env}}{{println .}}{{end}}' | Select-String API_AUTH_MODE`. If `entra`, restart with `$env:API_AUTH_MODE="development"` |

### Stage: `preparing` — stuck or `failed`

**Symptom:** Status stuck at `preparing` for more than 2 minutes, or shows `failed`.

**Diagnosis:**
```powershell
docker logs wafagent-preparation --since 10m 2>&1 |
    Select-String "ERROR|failed|exception|InvalidAssessmentScope|CrossTenantAuth|KeyVaultAccess|ResourceDiscovery|SubscriptionNotFound"
```

| Log event | Cause | Fix |
|---|---|---|
| `"error_type":"InvalidAssessmentScopeError","error_message":"No credential registered"` | Step 6.3 was skipped | Re-run the `psql` INSERT from step 6.3 |
| `"error_type":"CrossTenantAuthError"` | Key Vault secret missing or malformed | Verify secret: `az keyvault secret show --vault-name <kv> --name <secret>` — value must be valid JSON with `tenant_id`, `client_id`, `client_secret` |
| `"error_type":"KeyVaultAccessError"` | Platform credential lacks Key Vault Secrets User | Verify role assignment: `az role assignment list --assignee $spClientId --scope $kvResourceId` |
| `"error_type":"ResourceDiscoveryError"` | Resource Graph API rate-limited | Wait 60 seconds; Service Bus auto-retries (lock = 5 min) |
| `"error_type":"SubscriptionNotFoundError"` | SP lacks Reader role on subscription | Re-run step 3.1a role assignment |

### Stage: `extracting` — stuck or batches failing

**Diagnosis:**
```powershell
docker logs wafagent-extraction --since 10m 2>&1 |
    Select-String "ERROR|batch_failed|CrossTenantAuth|KeyVaultAccess|AzureRateLimit|stage_failed"
```

| Error | Cause | Fix |
|---|---|---|
| `"stage":"credential"` | Same as preparation auth errors | See preparing stage above |
| `"stage":"resource_graph"` | Resource Graph rate limit | Wait for Service Bus retry (~5 min); check Azure Resource Graph quota |
| Batch stays `in_progress` indefinitely | Extraction agent pod crashed mid-batch | `docker restart wafagent-extraction`; Service Bus re-delivers unacknowledged message within lock duration |

### Stage: `extracting` — Reasoning Agent failures

**Diagnosis:**
```powershell
docker logs wafagent-reasoning --since 15m 2>&1 |
    Select-String "ERROR|LLMQuota|batch_failed|stage_failed|WafEnrichment"
```

| Error | Cause | Fix |
|---|---|---|
| `"error_type":"LLMQuotaExhaustedError"` | Gemini free-tier daily quota exhausted | Check quota at https://aistudio.google.com → API quotas; quota resets at midnight UTC |
| `"error_type":"WafEnrichmentError"` | Finding mapped to WAF rule with empty WAF codes | Check `waf_control_mapping.json` has entries for all rule IDs in `rule_definitions.py` |
| No `findings_inserted` logs | All resources passed or had NOT_APPLICABLE rules | Normal if subscription has well-configured resources or `pillar_filter` is narrow |
| `GEMINI_API_KEY` errors | Key invalid or missing from container env | Set key in `.env`, then: `docker compose -f docker-compose.dev.yml --profile full up -d reasoning-agent` |

### Stage: `reporting` — stuck or upload failures

**Diagnosis:**
```powershell
docker logs wafagent-reporting --since 5m 2>&1 |
    Select-String "ERROR|blob_upload_failed|reports_saved_locally|assessment_completed|degraded"
```

| Log event | Cause | Fix |
|---|---|---|
| `"event":"reporting.handler.blob_upload_failed"` | Storage account or container unreachable | Verify `STORAGE_ACCOUNT_NAME` and container exist; verify Storage Blob Data Contributor role assignment |
| `"event":"reporting.handler.reports_saved_locally","degraded":true` | Blob upload failed; reports written to `/tmp/reports/{assessment_id}/` inside container. **These will not survive a pod restart.** | Copy out immediately: `docker cp wafagent-reporting:/tmp/reports/$assessmentId/report.xlsx .` — then investigate the blob upload failure |
| `KeyError` in Excel/PDF generation | Finding field missing or unexpected format | Check Python traceback in logs; file a bug with the exact stack trace |
| Assessment stays `reporting` for more than 5 minutes | Reporting agent crashed during generation | `docker restart wafagent-reporting`; Service Bus re-delivers within lock duration |

### API: `readyz` returns 503

```powershell
docker logs wafagent-api --since 2m 2>&1 | Select-String "alembic|migration|pool|ERROR"
```

Alembic migrations run via the `wafagent-migrate` container. If migration fails, the DB pool does not initialize. Fix: `docker compose -f docker-compose.dev.yml restart migrate api`.

### API: returns 401 Unauthorized on all requests

```powershell
docker inspect wafagent-api --format '{{range .Config.Env}}{{println .}}{{end}}' |
    Select-String "API_AUTH_MODE"
```

**Expected:** `API_AUTH_MODE=development`

If it shows `API_AUTH_MODE=entra`:
```powershell
$env:API_AUTH_MODE = "development"
$env:APP_ENV       = "development"
docker compose -f docker-compose.dev.yml --profile full up -d api
```

> **Note:** `API_AUTH_MODE` defaults to `entra` in `docker-compose.dev.yml`. It must be explicitly overridden to `development` in your shell environment (or in `.env`) before starting containers for the demo.

---

## 20. Cleanup

After the demo, remove the deliberately weakened Azure resources:

```powershell
# Set these if running cleanup in a new shell session:
# $weakStorage   = "stwafweak1234"   # the actual name from step 6.1
# $resourceGroup = "rg-waf-demo6"

az storage account delete `
    --name $weakStorage `
    --resource-group $resourceGroup `
    --yes

az group delete `
    --name $resourceGroup `
    --yes --no-wait

Write-Host "Non-compliant resources deleted." -ForegroundColor Green
```

Stop all platform services:

```powershell
docker compose -f docker-compose.dev.yml --profile full down
```

Restore environment:

```powershell
Remove-Item Env:\APP_ENV       -ErrorAction SilentlyContinue
Remove-Item Env:\API_AUTH_MODE -ErrorAction SilentlyContinue
```

> **Note:** `.env` defaults `APP_ENV=development` and `API_AUTH_MODE=development` for local development. Do not commit `.env` to version control — it is listed in `.gitignore`.

---

## Appendix A: Complete API Surface

| Method | Path | Status | Auth Required | Purpose |
|---|---|---|---|---|
| GET | `/healthz` | 200 | None | Liveness probe |
| GET | `/readyz` | 200 / 503 | None | Readiness probe (database + redis) |
| POST | `/v1/assessments` | **202** | TENANT_ADMIN / PLATFORM_ADMIN | Create a new WAF assessment |
| GET | `/v1/assessments` | 200 | Any authenticated role | List assessments for caller's tenant |
| GET | `/v1/assessments/{id}` | 200 | Any authenticated role | Get assessment by ID |
| POST | `/v1/assessments/{id}/cancel` | 200 | TENANT_ADMIN / PLATFORM_ADMIN | Request cancellation |
| GET | `/v1/assessments/{id}/findings` | 200 | Any authenticated role | List findings (query params: `severity`, `pillar`, `finding_status`, `limit`, `cursor`) |
| GET | `/v1/assessments/{id}/report` | 200 / 404 | Any authenticated role | Get report metadata + blob paths |
| GET | `/v1/human-review/controls` | 200 | Any authenticated role | List all 4 human-review controls with questionnaires |
| GET | `/v1/human-review/controls/{code}` | 200 | Any authenticated role | Get one control (SE-10, OE-03, OE-04, CO-09) |
| GET | `/v1/human-review/assessments/{id}/reviews` | 200 | Any authenticated role | List all reviews for an assessment |
| GET | `/v1/human-review/assessments/{id}/reviews/{code}` | 200 | Any authenticated role | Get one review by control code |
| POST | `/v1/human-review/assessments/{id}/reviews` | **201** | TENANT_ADMIN / PLATFORM_ADMIN | Submit a human review |
| PUT | `/v1/human-review/assessments/{id}/reviews/{code}` | 200 | TENANT_ADMIN / PLATFORM_ADMIN | Update an existing review |
| GET | `/v1/human-review/assessments/{id}/summary` | 200 | Any authenticated role | Get coverage summary (automated + human combined) |

**Development mode auth:** When `API_AUTH_MODE=development`, all requests are automatically authenticated as `PLATFORM_ADMIN` with `tenant_id=00000000-0000-0000-0000-000000000001`. No Authorization header is required.

**Interactive API docs:** Available at `http://localhost:8000/docs` **only** when `APP_ENV=development`. Disabled in staging and production.

---

## Appendix B: WAF Pillar Names (exact values for API requests)

The `pillar_filter` field in `POST /v1/assessments` accepts these exact strings (case-sensitive):

```
Security
Reliability
Cost Optimization
Operational Excellence
Performance Efficiency
```

The `pillar` query parameter in `GET /v1/assessments/{id}/findings` accepts lowercase database values:

```
security
reliability
cost_optimization
operational_excellence
performance_efficiency
```

The `finding_status` query parameter in `GET /v1/assessments/{id}/findings` accepts:

```
open
acknowledged
resolved
suppressed
```

---

## Appendix C: Excel Workbook Sheet Index (29 sheets)

| Sheet | Name | Content |
|---|---|---|
| 1 | Executive Summary | Risk rating, key findings, top-5 actions, 30/60/90-day compliance projection, management narrative |
| 2 | Executive Dashboard | Four enterprise scores + Top-5 risk table |
| 3 | Visual Dashboard | KPI grid, risk heatmap, pillar bars, severity donut, clickable table of contents |
| 4 | Architecture Diagram | Subscription → resource group → resource type hierarchy, color-coded by compliance |
| 5 | Resource Inventory | Per-resource-type compliance table (total, compliant, non-compliant, critical/high counts) |
| 6 | Pillar Scorecard | All-pillar scores vs. WAF benchmark targets (Security 90%, Reliability 85%, etc.) |
| 7 | Security | Security pillar findings — color-coded by severity |
| 8 | Reliability | Reliability pillar findings |
| 9 | Operational Excellence | Operational Excellence findings |
| 10 | Performance Efficiency | Performance Efficiency findings |
| 11 | Cost Optimization | Cost Optimization findings |
| 12 | Business Impact | Findings classified by business impact category (Security Exposure, Availability Risk, Financial Waste, Operational Risk, Performance Degradation) |
| 13 | AI Executive Insights | Gemini-generated strategic insights with confidence scores |
| 14 | Traceability Matrix | Finding → Rule → WAF Code → Microsoft URL (one row per WAF code per finding) |
| 15 | Human Reviews | SE-10 / OE-03 / OE-04 / CO-09 review status, scores, answers, and evidence |
| 16 | Trend Analysis | Historical compliance data across up to 6 prior assessments (or "Not Available") |
| 17 | Grouped Findings | Findings deduplicated by rule, showing affected resource count per group |
| 18 | Remediation Detail | Detailed fix instructions per finding type with Azure CLI and portal steps |
| 19 | Remediation Roadmap | 30/60/90-day prioritised remediation plan by effort and impact |
| 20 | Remediation Playbooks | Step-by-step runbooks for highest-impact finding types |
| 21 | Implementation Roadmap | Enterprise phased plan: quick wins → medium-term → strategic |
| 22 | All Findings | Complete flat table of every finding across all pillars (all columns) |
| 23 | Coverage Report | Per-WAF-control coverage status |
| 24 | Gap Analysis | Controls with no findings; assessment gaps |
| 25 | Compliance Mapping | ISO 27001, NIST CSF, CIS control cross-references |
| 26 | Risk Matrix | 5×5 severity/likelihood matrix with findings plotted |
| 27 | Audit Trail | Assessment lifecycle event log with timestamps |
| 28 | Glossary | Definitions for WAF terms, severity levels, pillar names |
| 29 | Methodology | Full scoring methodology documentation for auditors |

---

## Appendix D: PDF Section Index (33 sections)

| # | Title | Content |
|---|---|---|
| 1 | Cover Page | Assessment ID, tenant, generation timestamp, classification banner |
| 2 | Executive Risk Statement | AI-generated narrative risk summary — overall posture in prose |
| 3 | Executive Summary | Risk rating, key risks, top-5 actions, compliance projection, management summary |
| 4 | Pillar Scorecard | All-pillar compliance bars with WAF benchmark targets |
| 5 | Security Scorecard | 5-category heat-bar: Identity & Access, Data Protection, Network Security, Operational Security, Governance |
| 6 | Executive Dashboard | Four enterprise scores + Top-5 risk table |
| 7 | Visual Dashboards | KPI grid, severity donut, pillar radar chart, risk heatmap |
| 8 | Resource Inventory | Per-resource-type compliance table + horizontal bar chart |
| 9 | Resource Group Breakdown | Per-resource-group compliance table + bar chart |
| 10 | Compliance Overview | All-pillar compliance table + bar chart |
| 11 | WAF Benchmark | Current pillar scores vs. Microsoft WAF target scores |
| 12 | Business Impact | Impact category analysis + finding distribution chart |
| 13 | Executive Insights | 3–5 AI-generated strategic insights with evidence and confidence scores |
| 14 | Architecture Topology | Hierarchy diagram: subscription → resource group → resource type |
| 15 | WAF Control Pages | One page per WAF control referenced by findings |
| 16 | Trend Analysis | Historical compliance trajectory (or "Not Yet Available" for first assessment) |
| 17 | Compliance Roadmap | Score projection with remediation milestones |
| 18 | Executive Remediation Roadmap | Top-20 priority remediations for executive review |
| 19 | Remediation Roadmap | Detailed remediation steps ordered by priority and impact |
| 20 | Remediation Playbooks | Step-by-step runbooks for high-impact finding types |
| 21 | Enterprise Remediation Roadmap | 30/60/90-day phased implementation plan |
| 22 | Human Review Results | SE-10, OE-03, OE-04, CO-09 review verdicts and scores |
| 23 | WAF Traceability Matrix | Finding → Rule → WAF Code → Microsoft URL (capped at 200 rows; full data in Excel Sheet 14) |
| 24 | Detailed Findings | Per-pillar finding tables with evidence JSON and recommendations |
| 25 | Executive Recommendations | Top-5 AI-generated strategic recommendations |
| 26 | Appendix | Full findings table + scoring methodology summary |
| 27 | Compliance Framework Mapping | ISO 27001, NIST CSF, CIS benchmark cross-references |
| 28 | Risk Matrix | 5×5 severity/likelihood matrix with findings plotted |
| 29 | Assessment Methodology | Full scoring formula documentation for auditors |
| 30 | Confidence Explanation | How deterministic (1.0) vs. LLM confidence scores are calculated |
| 31 | Limitations | What the platform does not assess and known limitations |
| 32 | Audit Trail | Assessment lifecycle event log |
| 33 | Glossary | Definitions for WAF terminology |

---

## Appendix E: Scoring Model Reference

### Pillar Score (per-pillar, 0–100)

```
weight(rule, resource) = severity_weight(rule.severity)
                         × resource_criticality(resource.resource_type)

pillar_score = weighted_passed / weighted_applicable × 100
```

`weighted_applicable` = sum of all applicable weights for that pillar
`weighted_passed`     = `weighted_applicable` minus sum of failing weights

### Severity Weights

| Severity | Weight |
|---|---|
| Critical | 10 |
| High | 7 |
| Medium | 5 |
| Low | 2 |
| Informational | 1 |

### Resource Criticality Multipliers

| Resource Type | Multiplier |
|---|---|
| Key Vault, SQL Server | 1.5 |
| SQL Database, Application Gateway | 1.4 |
| Storage Account | 1.3 |
| Virtual Machine, App Service, AKS, Cosmos DB | 1.2 |
| Service Bus, Event Hub, Redis, MySQL, PostgreSQL | 1.1 |
| VMSS, App Service Plan | 1.0 |
| Load Balancer, NSG, Activity Log Alerts | 0.9 |
| CDN Profile, CDN Endpoint | 0.8 |
| NIC, Public IP | 0.7 |
| Managed Disk, Snapshot | 0.6 |
| All other types | 1.0 (default) |

### Overall Compliance Score

```
overall = Σ(pillar_score[P] × pillar_weight[P])
```

| Pillar | Weight |
|---|---|
| Security | 30% |
| Reliability | 20% |
| Performance Efficiency | 20% |
| Operational Excellence | 15% |
| Cost Optimization | 15% |

### Overall Risk Score

```
risk = min(100, (100 − overall_compliance) + (critical + high) / total_findings × 10)
```

### WAF Benchmark Targets

| Pillar | Target | Rationale |
|---|---|---|
| Security | 90% | Enterprise minimum — SOC 2 / ISO 27001 |
| Reliability | 85% | 99.9% availability SLA baseline |
| Operational Excellence | 85% | ITIL / DevOps maturity baseline |
| Cost Optimization | 80% | Eliminates clear waste with workload headroom |
| Performance Efficiency | 80% | Solid baseline for non-critical paths |

### NOT_APPLICABLE Handling

Rules that evaluate as NOT_APPLICABLE for a resource (the resource type does not match the rule's applicability condition) are never stored as findings and are counted as passed in the weighted denominator. This is consistent with Microsoft WAF guidance that NOT_APPLICABLE controls do not reduce the score.
