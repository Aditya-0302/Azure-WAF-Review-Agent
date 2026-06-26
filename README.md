# AI-Powered Azure WAF Review Agent

This README is a literal step-by-step guide for running the full project. It is
written for someone who is new to Azure, Python, Docker, and APIs.

Last updated: June 19, 2026.

## Read This First

Follow the parts in order. Do not jump straight to the final commands.

### LLM Provider

This project supports two LLM providers. Choose one before you start:

| | OPTION A — Gemini (Recommended) | OPTION B — Azure OpenAI |
| --- | --- | --- |
| **Requires** | Free Google API key | Azure subscription + model deployment |
| **Local dev** | Works immediately | Blocked by subscription policy on some accounts |
| **Setup time** | 2 minutes | 30–60 minutes |
| **Cost** | Free tier available | Billed per token |

**For first-time setup, use OPTION A (Gemini).** Azure OpenAI support is fully
preserved and can be switched on at any time by changing one environment variable.

### What You Need for Full Functionality

- A local PostgreSQL database for project data.
- Local Redis for cache/background support.
- Azure Service Bus for messages between the API and agents
  (or the local emulator for pure-local development).
- Azure Key Vault for cross-tenant subscription credentials.
- **Gemini API key** (or Azure OpenAI endpoint) for AI reasoning.
- Azure Storage for generated reports.
- The API server.
- Four background agents: preparation, extraction, reasoning, and reporting.
- A seeded tenant, user, subscription credential, and WAF rules in the database.

## Local Development Fast Path

Use this path when you want to run the API and agents locally **without any
Azure account setup**. `API_AUTH_MODE=development` skips JWT validation and
injects a synthetic `PLATFORM_ADMIN` identity. No app registration, no Entra
admin consent, and no `az account get-access-token` are required.

**Minimum requirements:** Docker Desktop, Python 3.12, a Gemini API key.

Parts 4–12 (Azure resource creation) and Part 20 (token acquisition) are not
required with this path.

Start agents (Parts 21–22) when you want the full pipeline. Skip them if you
only need to test the API layer.

## What This Project Does

This project reviews Azure resources against Azure Well-Architected Framework
ideas.

In plain English:

- You connect the project to your Azure subscription.
- The API creates an assessment request.
- The preparation agent finds resources to review.
- The extraction agent pulls resource properties from Azure.
- The reasoning agent applies rules and LLM reasoning (Gemini or Azure OpenAI).
- The reporting agent creates reports and stores them in Azure Storage.

## Beginner Glossary

| Word | Meaning |
| --- | --- |
| Terminal | The app where you paste commands. On Windows, use PowerShell. |
| Command | A line of text you paste into the terminal and run with Enter. |
| Project folder | The folder that contains this README file. |
| `.env` file | A settings file for local URLs, API keys, and secrets. |
| Docker | A tool that runs services like PostgreSQL on your computer. |
| Container | One service running inside Docker. |
| PostgreSQL | The database used by this project. |
| Redis | A small fast storage/cache service. |
| API | The local web server for this project. |
| Agent | A background worker that processes assessment steps. |
| LLM | Large Language Model — the AI that evaluates WAF rules. |
| Gemini | Google's LLM service. Recommended default for this project. |
| Azure OpenAI | Microsoft's LLM service. Optional enterprise path. |
| Azure subscription | The Azure account area where resources are created. |
| Service Bus | Azure message queue used by the API and agents. |
| Key Vault | Azure service for storing secrets safely. |
| Tenant ID | The ID of your Microsoft/Azure organization. |
| Client ID | The ID of an Azure app registration. |
| Object ID | The ID of a user, app, or service in Azure AD/Entra ID. |
| Bearer token | Login proof sent to protected API routes. |
| Migration | A database setup command that creates tables. |

## Part 1: Install Required Tools

Install these tools first.

| Tool | Why you need it | Check command |
| --- | --- | --- |
| Python 3.12 or newer | Runs the API and agents | `python --version` |
| Git | Useful for source control | `git --version` |
| Docker Desktop | Runs PostgreSQL and Redis locally | `docker --version` |
| Azure CLI | Creates Azure resources and signs in | `az version` |

Install links:

- Python: <https://www.python.org/downloads/>
- Git: <https://git-scm.com/downloads>
- Docker Desktop: <https://docs.docker.com/desktop/>
- Azure CLI: <https://learn.microsoft.com/cli/azure/install-azure-cli>

After installing, close and reopen PowerShell. Then run:

```powershell
python --version
git --version
docker --version
az version
```

If all four commands print versions, continue.

## Part 2: Open the Project Folder

On Windows:

1. Open the project folder in File Explorer.
2. Click the address bar at the top.
3. Type `powershell`.
4. Press Enter.

Check that you are in the correct folder:

```powershell
Get-ChildItem
```

You should see files and folders like this:

```text
README.md
.env.example
docker-compose.dev.yml
src
tests
```

Keep using this PowerShell window unless a later step asks you to open another
terminal.

## Part 3: Choose Azure Names

Azure resource names must often be globally unique. Choose one short suffix.

Rules for the suffix:

- Use lowercase letters and numbers only.
- Do not use spaces.
- Keep it short. Example: `yoursuffix`.

In PowerShell, paste this block and replace `yoursuffix` with your own suffix:

```powershell
$SUFFIX = "yoursuffix"
$RG = "rg-wafagent-demo"
$LOC = "southeastasia"
$KV = "kv-waf-$SUFFIX"
$STORAGE = "stwaf$SUFFIX"
$SB = "sb-waf-$SUFFIX"
$API_APP_NAME = "waf-agent-api-demo-$SUFFIX"
$READER_SP_NAME = "sp-wafagent-demo-reader-$SUFFIX"
```

Check the names:

```powershell
$RG
$KV
$STORAGE
$SB
$API_APP_NAME
$READER_SP_NAME
```

Important: the storage account name must not contain hyphens. That is why it is
`stwaf$SUFFIX`, not `st-waf-$SUFFIX`.

## Part 4: Sign In to Azure

Sign in:

```powershell
az login --use-device-code
```

A browser opens. Sign in with the account that has your Azure subscription.

List your subscriptions:

```powershell
az account list --output table
```

Set your subscription as active:

```powershell
az account set --subscription "PASTE-YOUR-SUBSCRIPTION-NAME-OR-ID"
```

Confirm the active subscription:

```powershell
az account show --output table
```

Save useful Azure IDs into PowerShell variables:

```powershell
$SUBSCRIPTION_ID = az account show --query id -o tsv
$AZURE_TENANT_ID = az account show --query tenantId -o tsv
$USER_OBJECT_ID = az ad signed-in-user show --query id -o tsv
```

Print them:

```powershell
$SUBSCRIPTION_ID
$AZURE_TENANT_ID
$USER_OBJECT_ID
```

You will paste these values into `.env` and the local database later.

## Part 5: Create the Azure Resource Group

```powershell
az group create --name $RG --location $LOC
```

Check it:

```powershell
az group show --name $RG --output table
```

## Part 6: Create the API App Registration

The API uses Microsoft Entra ID tokens for protected routes. This creates the
Azure app identity used by those tokens.

### Step 6.1: Create the App Registration

```powershell
$API_CLIENT_ID = az ad app create --display-name $API_APP_NAME --sign-in-audience AzureADMyOrg --query appId -o tsv
$JWT_AUDIENCE = "api://$API_CLIENT_ID"
az ad app update --id $API_CLIENT_ID --identifier-uris $JWT_AUDIENCE
```

Print the values:

```powershell
$API_CLIENT_ID
$JWT_AUDIENCE
```

You will paste them into `.env` later:

```env
AZURE_CLIENT_ID=PASTE-API-CLIENT-ID-HERE
JWT_AUDIENCE=api://PASTE-API-CLIENT-ID-HERE
```

### Step 6.2: Add API Roles in the Azure Portal

1. Open <https://portal.azure.com/>
2. Search for `App registrations`.
3. Open the app named `waf-agent-api-demo-<your-suffix>`.
4. Open `App roles`.
5. Click `Create app role`.
6. Create this role:

   ```text
   Display name: WafAgent Tenant Admin
   Allowed member types: Users/Groups
   Value: WafAgent.TenantAdmin
   Description: Can create and manage WAF assessments for one tenant.
   Do you want to enable this app role?: Yes
   ```

7. Click `Apply`.
8. Create this second role:

   ```text
   Display name: WafAgent Tenant Viewer
   Allowed member types: Users/Groups
   Value: WafAgent.TenantViewer
   Description: Can view WAF assessments for one tenant.
   Do you want to enable this app role?: Yes
   ```

9. Click `Apply`.
10. Create this third role:

    ```text
    Display name: WafAgent Platform Admin
    Allowed member types: Users/Groups
    Value: WafAgent.PlatformAdmin
    Description: Can administer the platform.
    Do you want to enable this app role?: Yes
    ```

11. Click `Apply`.

### Step 6.3: Assign Yourself the Tenant Admin Role

1. In Azure Portal, search for `Enterprise applications`.
2. Search for the app named `waf-agent-api-demo-<your-suffix>`.
3. Open it.
4. Open `Users and groups`.
5. Click `Add user/group`.
6. Select your own user.
7. Select the role `WafAgent Tenant Admin`.
8. Click `Assign`.

This role is important. Without it, protected API calls return `403`.

## Part 7: Create Azure Service Bus

Service Bus lets the API and agents pass work to each other.

Create the namespace:

```powershell
az servicebus namespace create --resource-group $RG --name $SB --location $LOC --sku Basic
```

Create the queues:

```powershell
$QUEUES = @(
  "assessment.created",
  "extraction.requested",
  "reasoning.requested",
  "reporting.requested",
  "assessment.cancelled",
  "webhook.delivery",
  "credential.health-check",
  "dlq-reprocess"
)

foreach ($Q in $QUEUES) {
  az servicebus queue create --resource-group $RG --namespace-name $SB --name $Q
}
```

Check the queues:

```powershell
az servicebus queue list --resource-group $RG --namespace-name $SB --query "[].name" -o table
```

The `.env` value will be:

```env
SERVICEBUS_NAMESPACE=sb-waf-yoursuffix.servicebus.windows.net
```

Use your actual Service Bus name, not `yoursuffix`.

## Part 8: Create Azure Key Vault

Key Vault stores the subscription reader credential.

```powershell
az keyvault create --name $KV --resource-group $RG --location $LOC
```

Get the Key Vault URL:

```powershell
$KEYVAULT_URI = az keyvault show --name $KV --query properties.vaultUri -o tsv
$KEYVAULT_URI
```

The `.env` value will be:

```env
KEYVAULT_URI=https://kv-waf-yoursuffix.vault.azure.net/
```

Give your signed-in Azure user permission to set and read secrets:

```powershell
az keyvault set-policy --name $KV --object-id $USER_OBJECT_ID --secret-permissions get list set delete
```

## Part 9: Create Azure Storage

Storage holds generated reports.

Create the storage account:

```powershell
az storage account create --name $STORAGE --resource-group $RG --location $LOC --sku Standard_LRS --kind StorageV2
```

Get a temporary storage key for creating containers:

```powershell
$STORAGE_KEY = az storage account keys list --account-name $STORAGE --resource-group $RG --query "[0].value" -o tsv
```

Create report containers:

```powershell
az storage container create --account-name $STORAGE --account-key $STORAGE_KEY --name reports
az storage container create --account-name $STORAGE --account-key $STORAGE_KEY --name audit-exports
```

Check them:

```powershell
az storage container list --account-name $STORAGE --account-key $STORAGE_KEY --query "[].name" -o table
```

The `.env` values will be:

```env
STORAGE_ACCOUNT_NAME=stwafyoursuffix
STORAGE_REPORTS_CONTAINER=reports
STORAGE_AUDIT_CONTAINER=audit-exports
```

## Part 10: Configure the LLM Provider

Choose OPTION A (Gemini, recommended) or OPTION B (Azure OpenAI).

---

### OPTION A — Google Gemini (Recommended)

No Azure subscription required for the LLM. Gemini is the default provider.

#### Step 10A.1: Get a Gemini API Key

1. Open <https://aistudio.google.com/app/apikey>
2. Sign in with your Google account.
3. Click **Create API key**.
4. Copy the key. It looks like `AIzaSy...`.

You will paste this into `.env`:

```env
LLM_PROVIDER=gemini
GEMINI_API_KEY=AIzaSy...your-key-here...
GEMINI_CHAT_MODEL=gemini-2.5-pro
```

That is all. No Azure model deployment needed.

---

### OPTION B — Azure OpenAI (Enterprise Path)

Use this if your organization requires Azure OpenAI. If Azure OpenAI deployment
is blocked by your subscription policy, use OPTION A instead.

#### Step 10B.1: Create the Azure OpenAI Resource

Use the Azure Portal:

1. Open <https://portal.azure.com/>
2. Search for `Azure OpenAI`.
3. Click `Create`.
4. Subscription: choose your subscription.
5. Resource group: choose `rg-wafagent-demo`.
6. Region: choose a region available to your subscription.
7. Name: enter `aoai-waf-<your-suffix>`.
8. Pricing tier: choose the lowest standard option shown.
9. Click `Review + create`.
10. Click `Create`.

After it is created, get the endpoint:

```powershell
$AOAI = "aoai-waf-$SUFFIX"
$AZURE_OPENAI_ENDPOINT = az cognitiveservices account show --name $AOAI --resource-group $RG --query properties.endpoint -o tsv
$AZURE_OPENAI_ENDPOINT
```

#### Step 10B.2: Deploy a Chat Model

1. Open your Azure OpenAI resource.
2. Open Azure AI Foundry or the model deployment page.
3. Create a chat model deployment with a pinned name, for example:

```text
gpt-4o-demo
```

#### Step 10B.3: Set the `.env` Values

```env
LLM_PROVIDER=azure
AZURE_OPENAI_ENDPOINT=https://aoai-waf-yoursuffix.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT_CHAT=gpt-4o-demo
AZURE_OPENAI_API_VERSION=2024-05-01-preview
```

#### Step 10B.4: Assign Yourself the OpenAI User Role

```powershell
$AOAI_ID = az cognitiveservices account show --name $AOAI --resource-group $RG --query id -o tsv
az role assignment create --assignee-object-id $USER_OBJECT_ID --assignee-principal-type User --role "Cognitive Services OpenAI User" --scope $AOAI_ID
```

---

## Part 11: Give Your Local Azure Login Access to Azure Services

When running on your laptop, the project uses your `az login` identity for
Azure services.

Get Azure resource IDs:

```powershell
$SB_ID = az servicebus namespace show --resource-group $RG --name $SB --query id -o tsv
$KV_ID = az keyvault show --name $KV --resource-group $RG --query id -o tsv
$STORAGE_ID = az storage account show --name $STORAGE --resource-group $RG --query id -o tsv
```

Assign roles to your signed-in user:

```powershell
az role assignment create --assignee-object-id $USER_OBJECT_ID --assignee-principal-type User --role "Azure Service Bus Data Owner" --scope $SB_ID
az role assignment create --assignee-object-id $USER_OBJECT_ID --assignee-principal-type User --role "Storage Blob Data Contributor" --scope $STORAGE_ID
```

If Azure says a role assignment already exists, that is fine.

## Part 12: Create Read-Only Azure Access for the Subscription

The project needs read-only access to the Azure subscription it reviews. This
creates a service principal with the `Reader` role.

```powershell
$READER = az ad sp create-for-rbac --name $READER_SP_NAME --role Reader --scopes "/subscriptions/$SUBSCRIPTION_ID" | ConvertFrom-Json
```

Convert it to the JSON format the project expects:

```powershell
$SECRET_OBJECT = @{
  tenant_id = $READER.tenant
  client_id = $READER.appId
  client_secret = $READER.password
} | ConvertTo-Json -Compress
```

Store it in Key Vault:

```powershell
az keyvault secret set --vault-name $KV --name demo-subscription-reader --value $SECRET_OBJECT
```

Check that the secret exists:

```powershell
az keyvault secret show --vault-name $KV --name demo-subscription-reader --query name -o tsv
```

You should see:

```text
demo-subscription-reader
```

Remember this exact name. The local database will use it later.

### Supported Key Vault Secret Formats

The API accepts four formats when reading a subscription reader secret from Key Vault.
All formats normalize to the same three required fields: `tenant_id`, `client_id`, `client_secret`.

**JSON (canonical — recommended):**

```json
{"tenant_id": "...", "client_id": "...", "client_secret": "..."}
```

This is what `ConvertTo-Json -Compress` produces above. Use this for new secrets.

**Format A — key=value per line:**

```text
tenant_id=<value>
client_id=<value>
client_secret=<value>
```

**Format B — key:value per line:**

```text
tenant_id:<value>
client_id:<value>
client_secret:<value>
```

**Format C — brace-wrapped, comma-separated key:value pairs:**

```text
{tenant_id:<value>,client_id:<value>,client_secret:<value>}
```

If a legacy format (A, B, or C) is detected the API logs `auth.cross_tenant.secret.legacy_format` with the secret name. Valid JSON secrets log nothing extra. Consider migrating legacy secrets to JSON to silence the warning.

## Part 13: Create the `.env` File

The `.env` file tells the project which database and services to use.

From the project folder:

```powershell
Copy-Item .env.example .env
```

Open `.env` in a text editor. Replace every value that says `PASTE-...` or
contains `yoursuffix`.

### OPTION A (Gemini) — Minimum Required `.env`

```env
# --- Application ---
APP_ENV=development
APP_VERSION=0.1.0
LOG_LEVEL=DEBUG
AUTH_MODE=default_chain
API_AUTH_MODE=development

# --- API Server ---
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=1

# --- PostgreSQL ---
DB_HOST=localhost
DB_PORT=5432
DB_NAME=wafagent
DB_USER=wafagent
DB_PASSWORD=changeme_local_only
DB_POOL_MIN_SIZE=2
DB_POOL_MAX_SIZE=10
DB_READONLY_HOST=
DB_READONLY_PORT=5432

# --- Redis ---
REDIS_URL=redis://localhost:6379/0
REDIS_MAX_CONNECTIONS=20

# --- Azure Service Bus ---
SERVICEBUS_NAMESPACE=sb-waf-yoursuffix.servicebus.windows.net
SERVICEBUS_CONNECTION_STRING=

# --- LLM Provider: Gemini ---
LLM_PROVIDER=gemini
GEMINI_API_KEY=PASTE-YOUR-GEMINI-API-KEY-HERE
GEMINI_CHAT_MODEL=gemini-2.5-pro
GEMINI_EMBED_MODEL=text-embedding-004

# --- Azure OpenAI (not needed for Gemini) ---
AZURE_OPENAI_ENDPOINT=
AZURE_OPENAI_DEPLOYMENT_CHAT=
AZURE_OPENAI_API_VERSION=2024-05-01-preview
AZURE_OPENAI_MAX_TOKENS=4096

# --- Azure Key Vault ---
KEYVAULT_URI=https://kv-waf-yoursuffix.vault.azure.net/

# --- Azure AI Search (reserved for future use, not required now) ---
SEARCH_ENDPOINT=
SEARCH_INDEX_NAME=waf-knowledge-v1

# --- Azure AD / Entra ID ---
AZURE_TENANT_ID=PASTE-AZURE-TENANT-ID-HERE
AZURE_CLIENT_ID=PASTE-API-CLIENT-ID-HERE
JWT_AUDIENCE=api://PASTE-API-CLIENT-ID-HERE

# --- Azure Storage ---
STORAGE_ACCOUNT_NAME=stwafyoursuffix
STORAGE_REPORTS_CONTAINER=reports
STORAGE_AUDIT_CONTAINER=audit-exports

# --- Telemetry ---
APPLICATIONINSIGHTS_CONNECTION_STRING=
OTEL_SERVICE_NAME=waf-api
OTEL_EXPORTER_ENABLED=false

# --- Feature flags ---
QUOTA_ENFORCEMENT_ENABLED=true
WEBHOOK_SIGNING_ENABLED=true

# --- Agent tuning ---
BATCH_SIZE=50
MAX_CONCURRENT_SUBSCRIPTIONS=5
LLM_TEMPERATURE=0.1
```

### OPTION B (Azure OpenAI) — Changes to the LLM section only

If you chose Azure OpenAI, change the LLM section to:

```env
# --- LLM Provider: Azure OpenAI ---
LLM_PROVIDER=azure
GEMINI_API_KEY=
GEMINI_CHAT_MODEL=gemini-2.5-pro
AZURE_OPENAI_ENDPOINT=https://aoai-waf-yoursuffix.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT_CHAT=gpt-4o-demo
AZURE_OPENAI_API_VERSION=2024-05-01-preview
AZURE_OPENAI_MAX_TOKENS=4096
```

### `.env` Copy/Paste Map

| `.env` key | What to paste |
| --- | --- |
| `GEMINI_API_KEY` | The key from <https://aistudio.google.com/app/apikey> (OPTION A) |
| `SERVICEBUS_NAMESPACE` | `sb-waf-<suffix>.servicebus.windows.net` |
| `AZURE_OPENAI_ENDPOINT` | Output of `$AZURE_OPENAI_ENDPOINT` (OPTION B only) |
| `AZURE_OPENAI_DEPLOYMENT_CHAT` | The chat deployment name you created (OPTION B only) |
| `KEYVAULT_URI` | Output of `$KEYVAULT_URI` |
| `AZURE_TENANT_ID` | Output of `$AZURE_TENANT_ID` |
| `AZURE_CLIENT_ID` | Output of `$API_CLIENT_ID` |
| `JWT_AUDIENCE` | Output of `$JWT_AUDIENCE` |
| `STORAGE_ACCOUNT_NAME` | Output of `$STORAGE` |
| `API_AUTH_MODE` | `development` for local dev (no JWT required); `entra` for full Azure AD validation |

Save the file. Do not upload `.env` to GitHub.

## Part 14: Start Docker Desktop

Open Docker Desktop and wait until it says Docker is running.

Check Docker:

```powershell
docker ps
```

If Docker is running, you will see a table. It is fine if the table has no
containers yet.

## Part 15: Start Local PostgreSQL and Redis

For the standard run, PostgreSQL and Redis run locally. Service Bus, Key Vault,
and Storage use Azure.

Start PostgreSQL and Redis:

```powershell
docker compose -f docker-compose.dev.yml up -d postgres redis
```

Check them:

```powershell
docker compose -f docker-compose.dev.yml ps
```

Check PostgreSQL:

```powershell
docker exec wafagent-postgres pg_isready -U wafagent -d wafagent
```

Expected:

```text
accepting connections
```

Check Redis:

```powershell
docker exec wafagent-redis redis-cli ping
```

Expected:

```text
PONG
```

## Part 16: Create the Python Virtual Environment

Create it:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run this once:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then activate again:

```powershell
.\.venv\Scripts\Activate.ps1
```

When activation works, your prompt usually starts with:

```text
(.venv)
```

## Part 17: Install Project Packages

Keep the virtual environment active. Run these commands from the project folder:

```powershell
python -m pip install --upgrade pip
python -m pip install -e "src/shared[dev]"
python -m pip install -e "src/api[dev]"
python -m pip install -e "src/agents/preparation[dev]"
python -m pip install -e "src/agents/extraction[dev]"
python -m pip install -e "src/agents/reasoning[dev]"
python -m pip install -e "src/agents/reporting[dev]"
```

The shared package includes `google-genai` for Gemini support. It installs
automatically with the command above.

Check imports:

```powershell
python -c "import waf_shared, waf_api; print('api imports ok')"
python -c "import waf_preparation, waf_extraction, waf_reasoning, waf_reporting; print('agent imports ok')"
python -c "from google import genai; print('gemini sdk ok')"
```

Expected:

```text
api imports ok
agent imports ok
gemini sdk ok
```

## Part 18: Create Database Tables

Run migrations:

```powershell
alembic upgrade head
```

Check that tables exist:

```powershell
docker exec wafagent-postgres psql -U wafagent -d wafagent -c "\dt"
```

You should see tables such as:

```text
tenants
tenant_users
subscription_credentials
assessments
assessment_batches
assessment_resources
waf_rules
assessment_findings
assessment_reports
```

## Part 19: Seed the Local Database

This section connects your Azure login, Azure subscription, Key Vault secret,
and local database together.

### Step 19.1: Save IDs Again

If you opened a new terminal, run this again:

```powershell
$SUBSCRIPTION_ID = az account show --query id -o tsv
$AZURE_TENANT_ID = az account show --query tenantId -o tsv
$USER_OBJECT_ID = az ad signed-in-user show --query id -o tsv
```

### Step 19.2: Create the Local Tenant Row

**Development mode** (`API_AUTH_MODE=development`): **skip this step.** The API
creates the synthetic development tenant (`id = 00000000-0000-0000-0000-000000000001`,
slug `dev-0000-0001`) automatically on first startup. No manual SQL is needed.

**Entra mode** (`API_AUTH_MODE=entra`): run this command to create a real tenant
row keyed on your Azure tenant ID:

```powershell
docker exec wafagent-postgres psql -U wafagent -d wafagent -c "INSERT INTO tenants (slug, display_name, azure_tenant_id, plan_tier, is_active) VALUES ('demo', 'Demo Tenant', '$AZURE_TENANT_ID'::uuid, 'standard', true) ON CONFLICT (slug) DO UPDATE SET display_name = EXCLUDED.display_name, azure_tenant_id = EXCLUDED.azure_tenant_id, is_active = true;"
```

Get the local WAF tenant ID (Entra mode only):

```powershell
$WAF_TENANT_ID = docker exec wafagent-postgres psql -U wafagent -d wafagent -t -A -c "SELECT id FROM tenants WHERE slug = 'demo';"
$WAF_TENANT_ID
```

Save this value. You will use it for end-to-end tests.

### Step 19.3: Create Tenant Quotas

**Development mode** (`API_AUTH_MODE=development`): **skip this step.** The API
automatically creates a permissive quota row (`max_concurrent_assessments = 100`,
`max_monthly_assessments = 10000`) for the synthetic tenant on first startup.

**Entra mode** (`API_AUTH_MODE=entra`): run this command to create the quota row
for your real tenant:

```powershell
docker exec wafagent-postgres psql -U wafagent -d wafagent -c "INSERT INTO tenant_quotas (tenant_id, max_concurrent_assessments, max_monthly_assessments, max_subscriptions_per_assessment, max_resources_per_assessment) VALUES ('$WAF_TENANT_ID'::uuid, 3, 20, 10, 5000) ON CONFLICT (tenant_id) DO UPDATE SET max_concurrent_assessments = 3, max_monthly_assessments = 20, max_subscriptions_per_assessment = 10, max_resources_per_assessment = 5000;"
```

### Step 19.4: Connect Your Azure User to the Local Tenant

**Development mode** (`API_AUTH_MODE=development`): **skip this step.** Route
handlers use the role from `request.state.auth` (always `PLATFORM_ADMIN` in dev
mode) and do not query `tenant_users`.

**Entra mode** (`API_AUTH_MODE=entra`): run this command to link your real Entra
object ID to the demo tenant:

```powershell
docker exec wafagent-postgres psql -U wafagent -d wafagent -c "INSERT INTO tenant_users (tenant_id, entra_oid, role, is_active) VALUES ('$WAF_TENANT_ID'::uuid, '$USER_OBJECT_ID'::uuid, 'tenant_admin', true) ON CONFLICT (tenant_id, entra_oid) DO UPDATE SET role = 'tenant_admin', is_active = true;"
```

### Step 19.5: Register the Subscription Credential

This row tells the project which Azure subscription to review and which Key
Vault secret contains the subscription reader credential.

```powershell
docker exec wafagent-postgres psql -U wafagent -d wafagent -c "INSERT INTO subscription_credentials (tenant_id, subscription_id, display_name, keyvault_secret_name, health) VALUES ('$WAF_TENANT_ID'::uuid, '$SUBSCRIPTION_ID'::uuid, 'Demo Azure Subscription', 'demo-subscription-reader', 'healthy') ON CONFLICT (tenant_id, subscription_id) DO UPDATE SET display_name = EXCLUDED.display_name, keyvault_secret_name = EXCLUDED.keyvault_secret_name, health = 'healthy';"
```

### Step 19.6: Seed WAF Rules

The reasoning agent needs rules in the `waf_rules` table. Run this seed block:

```powershell
@'
INSERT INTO waf_rules (
  rule_id, pillar, resource_types, evaluation_type, condition_dsl,
  prompt_template_ref, severity, title, description, recommendation,
  is_active, version
) VALUES
(
  'STORAGE-SECURE-TRANSFER',
  'security',
  ARRAY['microsoft.storage/storageaccounts'],
  'deterministic',
  '{"op":"bool_eq","path":"properties.supportsHttpsTrafficOnly","value":true}'::jsonb,
  NULL,
  'high',
  'Storage account should require secure transfer',
  'Storage accounts should reject non-HTTPS traffic.',
  'Enable secure transfer required on the storage account.',
  true,
  1
),
(
  'STORAGE-MIN-TLS-12',
  'security',
  ARRAY['microsoft.storage/storageaccounts'],
  'deterministic',
  '{"op":"eq","path":"properties.minimumTlsVersion","value":"TLS1_2"}'::jsonb,
  NULL,
  'medium',
  'Storage account should use TLS 1.2 or newer',
  'Older TLS versions can weaken transport security.',
  'Set the storage account minimum TLS version to TLS 1.2 or newer.',
  true,
  1
),
(
  'VM-ZONES-REVIEW',
  'reliability',
  ARRAY['microsoft.compute/virtualmachines'],
  'llm',
  NULL,
  'vm-zones-review',
  'medium',
  'Virtual machines should be reviewed for zone resilience',
  'Zone placement can improve availability for supported workloads.',
  'Use availability zones, availability sets, or another resilience pattern where appropriate.',
  true,
  1
),
(
  'PUBLIC-IP-NON-BASIC',
  'reliability',
  ARRAY['microsoft.network/publicipaddresses'],
  'deterministic',
  '{"op":"ne","path":"sku.name","value":"Basic"}'::jsonb,
  NULL,
  'medium',
  'Public IP addresses should avoid Basic SKU',
  'Basic public IP addresses have fewer resiliency and security capabilities.',
  'Use Standard SKU public IP addresses for production workloads.',
  true,
  1
)
ON CONFLICT (rule_id) DO UPDATE SET
  pillar = EXCLUDED.pillar,
  resource_types = EXCLUDED.resource_types,
  evaluation_type = EXCLUDED.evaluation_type,
  condition_dsl = EXCLUDED.condition_dsl,
  prompt_template_ref = EXCLUDED.prompt_template_ref,
  severity = EXCLUDED.severity,
  title = EXCLUDED.title,
  description = EXCLUDED.description,
  recommendation = EXCLUDED.recommendation,
  is_active = true,
  updated_at = NOW();
'@ | docker exec -i wafagent-postgres psql -U wafagent -d wafagent
```

Note: `VM-ZONES-REVIEW` uses `evaluation_type='llm'` which triggers the Gemini
(or Azure OpenAI) reasoning pipeline. The other three rules are deterministic.

Check rule count:

```powershell
docker exec wafagent-postgres psql -U wafagent -d wafagent -c "SELECT rule_id, pillar, evaluation_type, severity, is_active FROM waf_rules ORDER BY rule_id;"
```

## Part 20: API Authentication

Skip or complete this part depending on your `API_AUTH_MODE` setting.

### Development mode (API_AUTH_MODE=development — default)

**No token required. Skip to Part 21.**

The API injects a synthetic `PLATFORM_ADMIN` identity on every request. You do
not need `az account get-access-token`, an app registration, or Entra admin
consent to call protected routes locally.

### Entra mode (API_AUTH_MODE=entra)

Complete these steps only if you set `API_AUTH_MODE=entra` in `.env`.

If you opened a new terminal, set these again:

```powershell
$API_CLIENT_ID = "PASTE-YOUR-API-CLIENT-ID-HERE"
$JWT_AUDIENCE = "api://$API_CLIENT_ID"
```

Get a token:

```powershell
$TOKEN = az account get-access-token --resource $JWT_AUDIENCE --query accessToken -o tsv
```

Check that a token was created:

```powershell
$TOKEN.Substring(0, 20)
```

You should see a short piece of text. Do not share the full token.

If protected API calls return `403`, your token probably does not include the
`WafAgent.TenantAdmin` role. Go back to Part 6 and assign yourself the app role.

## Part 21: Start the Full Project

You will use multiple terminals. Each terminal must be opened in the project
folder. Each terminal must activate the virtual environment first:

```powershell
.\.venv\Scripts\Activate.ps1
```

### Terminal 1: API Server

```powershell
uvicorn waf_api.main:app --host 0.0.0.0 --port 8000 --reload
```

Leave this terminal open.

### Terminal 2: Preparation Agent

```powershell
python -m waf_preparation.main
```

Leave this terminal open.

### Terminal 3: Extraction Agent

```powershell
python -m waf_extraction.main
```

Leave this terminal open.

### Terminal 4: Reasoning Agent

The reasoning agent will log which LLM provider it is using at startup:

```text
reasoning.main.starting  llm_provider=gemini
reasoning.main.llm_provider_ready  model=gemini-2.5-pro
```

```powershell
python -m waf_reasoning.main
```

Leave this terminal open.

### Terminal 5: Reporting Agent

```powershell
python -m waf_reporting.main
```

Leave this terminal open.

### Terminal 6: API Commands

Use this terminal to create and check assessments.

Activate the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

## Part 22: Check the API

Health check:

```powershell
Invoke-RestMethod http://localhost:8000/healthz
```

Expected:

```text
status
------
ok
```

Readiness check:

```powershell
Invoke-RestMethod http://localhost:8000/readyz
```

Expected:

```text
status checks
------ ------
ok     @{database=ok; redis=ok}
```

Open API docs in your browser:

```text
http://localhost:8000/docs
```

## Part 23: Create a Full Assessment

In Terminal 6, set the subscription to review. If you have Azure CLI logged in:

```powershell
$SUBSCRIPTION_ID = az account show --query id -o tsv
```

If you are running in development mode without an Azure account, use any valid
UUID as a placeholder:

```powershell
$SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000"
```

Create the request body:

```powershell
$BODY = @{
  idempotency_key = ([guid]::NewGuid().ToString())
  subscription_ids = @($SUBSCRIPTION_ID)
  pillar_filter = @("Security", "Reliability", "Cost Optimization", "Operational Excellence", "Performance Efficiency")
  tag_filter = $null
} | ConvertTo-Json -Depth 5
```

**Development mode** (`API_AUTH_MODE=development` — no token required):

```powershell
$CREATE_RESPONSE = Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:8000/api/v1/assessments" `
  -Headers @{ "Content-Type" = "application/json" } `
  -Body $BODY
```

**Entra mode** (`API_AUTH_MODE=entra` — include the Bearer token from Part 20):

```powershell
$CREATE_RESPONSE = Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:8000/api/v1/assessments" `
  -Headers @{
    Authorization = "Bearer $TOKEN"
    "Content-Type" = "application/json"
  } `
  -Body $BODY
```

Print the response:

```powershell
$CREATE_RESPONSE
```

Save the assessment ID:

```powershell
$ASSESSMENT_ID = $CREATE_RESPONSE.id
$ASSESSMENT_ID
```

## Part 24: Watch the Assessment Finish

Check status:

**Development mode** (`API_AUTH_MODE=development` — no token required):

```powershell
Invoke-RestMethod `
  -Method Get `
  -Uri "http://localhost:8000/api/v1/assessments/$ASSESSMENT_ID"
```

**Entra mode** (`API_AUTH_MODE=entra` — include the Bearer token from Part 20):

```powershell
Invoke-RestMethod `
  -Method Get `
  -Uri "http://localhost:8000/api/v1/assessments/$ASSESSMENT_ID" `
  -Headers @{ Authorization = "Bearer $TOKEN" }
```

Run the command every few seconds until the status becomes:

```text
completed
```

Other possible statuses while it is running:

```text
pending
preparing
extracting
reasoning
reporting
partial_failure
failed
cancelled
```

If it becomes `failed`, check the terminal logs for the API and agents.

## Part 25: View Findings

**Development mode** (`API_AUTH_MODE=development` — no token required):

```powershell
Invoke-RestMethod `
  -Method Get `
  -Uri "http://localhost:8000/api/v1/assessments/$ASSESSMENT_ID/findings"
```

**Entra mode** (`API_AUTH_MODE=entra` — include the Bearer token from Part 20):

```powershell
Invoke-RestMethod `
  -Method Get `
  -Uri "http://localhost:8000/api/v1/assessments/$ASSESSMENT_ID/findings" `
  -Headers @{ Authorization = "Bearer $TOKEN" }
```

It is possible for a small or mostly compliant subscription to have zero
findings. That does not mean the pipeline failed.

## Part 26: View the Report

**Development mode** (`API_AUTH_MODE=development` — no token required):

```powershell
Invoke-RestMethod `
  -Method Get `
  -Uri "http://localhost:8000/api/v1/assessments/$ASSESSMENT_ID/report"
```

**Entra mode** (`API_AUTH_MODE=entra` — include the Bearer token from Part 20):

```powershell
Invoke-RestMethod `
  -Method Get `
  -Uri "http://localhost:8000/api/v1/assessments/$ASSESSMENT_ID/report" `
  -Headers @{ Authorization = "Bearer $TOKEN" }
```

Expected:

```text
A response with a PDF URL, XLSX URL, or stored report information.
```

Also check the Azure Storage container:

```powershell
az storage blob list --account-name $STORAGE --container-name reports --auth-mode login --query "[].name" -o table
```

## Part 27: Run Tests

Keep Docker running and the virtual environment active.

Run unit tests:

```powershell
pytest tests/unit -v
```

Run integration tests:

```powershell
pytest tests/integration -v
```

Run live Azure discovery tests:

```powershell
$env:AZURE_INTEGRATION_TESTS = "1"
pytest tests/integration/discovery -v
```

Run end-to-end tests after the API and agents are running:

```powershell
$env:E2E_API_BASE_URL = "http://localhost:8000"
$env:E2E_TENANT_ID = $WAF_TENANT_ID
$env:E2E_SUBSCRIPTION_ID = $SUBSCRIPTION_ID
# E2E_BEARER_TOKEN: omit when API_AUTH_MODE=development (tests run without a token).
# Set to a real token when API_AUTH_MODE=entra:
#   $env:E2E_BEARER_TOKEN = $TOKEN
pytest tests/e2e -v
```

## Part 28: Optional Docker Full Profile

The clearest beginner path is Docker for PostgreSQL and Redis, plus Python
terminals for the API and agents.

You can also ask Docker Compose to build and start the API and agents:

```powershell
docker compose -f docker-compose.dev.yml --profile full up --build
```

Use this when you want all services in containers. The reasoning-agent container
reads `LLM_PROVIDER`, `GEMINI_API_KEY`, and other LLM settings from your `.env`
file automatically.

## Part 29: Stop Everything

Stop the API and agents:

```text
Press Ctrl+C in each terminal.
```

Stop PostgreSQL and Redis but keep data:

```powershell
docker compose -f docker-compose.dev.yml stop
```

Stop containers:

```powershell
docker compose -f docker-compose.dev.yml down
```

Stop containers and delete local database data:

```powershell
docker compose -f docker-compose.dev.yml down -v
```

Deactivate Python virtual environment:

```powershell
deactivate
```

Delete Azure resources when you are fully done:

```powershell
az group delete --name $RG --yes --no-wait
```

Only run that delete command when you are sure everything in
`rg-wafagent-demo` can be removed.

## Development Authentication

The API supports two authentication modes, controlled by the `API_AUTH_MODE`
environment variable.

| `API_AUTH_MODE` | Behavior |
| --- | --- |
| `entra` | Full Azure AD JWT validation (production default) |
| `development` | JWT validation skipped; synthetic identity injected |

> **Security note:** `API_AUTH_MODE=development` is explicitly forbidden when
> `APP_ENV=production`. The API process will refuse to start with that
> combination.

### When to use `API_AUTH_MODE=development`

Use it when you want to call the API locally without obtaining a real Azure AD
token — for example, while working on a feature before Entra ID is configured,
or when running automated tests that do not need real credentials.

### What development mode does

When `API_AUTH_MODE=development`:

1. The `Authorization: Bearer …` header is **not required**. Requests without
   it are accepted.
2. Every request receives a synthetic `AuthContext` with:

   ```text
   tenant_id : 00000000-0000-0000-0000-000000000001
   user_id   : 00000000-0000-0000-0000-000000000002
   role      : PLATFORM_ADMIN
   ```

3. The API logs a warning at startup:

   ```text
   Development authentication enabled. JWT validation is disabled.
   Never deploy with API_AUTH_MODE=development.
   ```

4. Swagger (`/docs`, `/redoc`, `/openapi.json`) is accessible without a token.
5. All protected routes work without a token — the synthetic identity satisfies
   all RBAC checks because `PLATFORM_ADMIN` is the highest role.

The synthetic `tenant_id` (`…0001`) does not correspond to a real row in the
`tenants` table. Routes that do database lookups keyed on tenant will return
empty results (not errors) unless you seed a matching row. For most local
testing this is fine.

### Enabling development mode

Set in `.env`:

```env
API_AUTH_MODE=development
```

Or export it before starting the API:

```powershell
$env:API_AUTH_MODE = "development"
uvicorn waf_api.main:app --host 0.0.0.0 --port 8000 --reload
```

When using Docker Compose, the `api` service already defaults to development
mode via `API_AUTH_MODE: "${API_AUTH_MODE:-development}"`. Override by exporting
`API_AUTH_MODE=entra` in the host shell before running `docker compose up`.

### Calling the API in development mode

No token needed:

```powershell
# Health check (always public)
Invoke-RestMethod http://localhost:8000/healthz

# List assessments — no Authorization header required in development mode
Invoke-RestMethod http://localhost:8000/v1/assessments `
  -Headers @{ "X-Request-ID" = "dev-test-001" }
```

### Switching back to Entra authentication

Set `API_AUTH_MODE=entra` in `.env` (or the host environment) and restart the
API. The API will then require a valid Azure AD JWT on every protected request:

```powershell
$TOKEN = az account get-access-token --resource $JWT_AUDIENCE --query accessToken -o tsv
Invoke-RestMethod http://localhost:8000/v1/assessments `
  -Headers @{ Authorization = "Bearer $TOKEN" }
```

### Note on `AUTH_MODE` vs `API_AUTH_MODE`

The project uses two distinct authentication variables:

| Variable | Controls | Values |
| --- | --- | --- |
| `AUTH_MODE` | Azure SDK credential chain (how the API obtains Azure tokens for Service Bus, Key Vault, etc.) | `default_chain`, `managed_identity`, `workload_identity`, `service_principal` |
| `API_AUTH_MODE` | Whether incoming HTTP requests require a valid Azure AD JWT | `entra`, `development` |

They are independent. You can have `AUTH_MODE=default_chain` (use your local
`az login` session for Azure SDK calls) and `API_AUTH_MODE=development` (no JWT
required on incoming requests) at the same time, which is the recommended local
development configuration.

---

## Troubleshooting

### `python` is not found

Close and reopen PowerShell. Then try:

```powershell
py --version
```

If `py` works, create the virtual environment with:

```powershell
py -3.12 -m venv .venv
```

### PowerShell will not activate `.venv`

Run:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then:

```powershell
.\.venv\Scripts\Activate.ps1
```

### Docker cannot connect

Open Docker Desktop and wait until it is fully running.

Then:

```powershell
docker ps
```

### Docker says a port is already in use

Common ports:

| Service | Port |
| --- | --- |
| API | `8000` |
| PostgreSQL | `5432` |
| Redis | `6379` |
| Service Bus emulator | `5671`, `5672`, `9080` |

Find the process using port `8000`:

```powershell
netstat -ano | findstr :8000
```

Stop the other app or change the API port.

### `alembic upgrade head` cannot connect

Start PostgreSQL:

```powershell
docker compose -f docker-compose.dev.yml up -d postgres
```

Check it:

```powershell
docker exec wafagent-postgres pg_isready -U wafagent -d wafagent
```

### `ModuleNotFoundError`

Activate the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

Reinstall packages:

```powershell
python -m pip install -e "src/shared[dev]"
python -m pip install -e "src/api[dev]"
python -m pip install -e "src/agents/preparation[dev]"
python -m pip install -e "src/agents/extraction[dev]"
python -m pip install -e "src/agents/reasoning[dev]"
python -m pip install -e "src/agents/reporting[dev]"
```

### Gemini API calls fail

Check:

- `LLM_PROVIDER=gemini` is set in `.env`.
- `GEMINI_API_KEY` is filled in (not empty).
- Your Gemini API key is valid. Test it at <https://aistudio.google.com/app/apikey>
- The reasoning agent log shows `llm_provider_ready  model=gemini-2.5-pro`.

Check the reasoning agent output for errors like:

```text
PERMISSION_DENIED: API key not valid
RESOURCE_EXHAUSTED: quota exceeded
```

If you see quota errors: the free tier has per-minute limits. Wait 60 seconds
and retry. For sustained workloads, enable billing on your Google AI account.

### Gemini returns a non-JSON response

The pipeline retries once with a simplified prompt. If both attempts fail, the
finding is recorded as `REVIEW` status rather than `PASS`/`FAIL`. This is safe
— the assessment still completes.

### Azure OpenAI calls fail (OPTION B)

Check:

- `LLM_PROVIDER=azure` in `.env`.
- `AZURE_OPENAI_ENDPOINT` is the endpoint URL (ends with `.openai.azure.com/`).
- `AZURE_OPENAI_DEPLOYMENT_CHAT` is the exact deployment name you created.
- Your subscription has model access.
- Your user has the `Cognitive Services OpenAI User` role.

### Switching from Gemini to Azure OpenAI (or vice versa)

Edit `.env` and change `LLM_PROVIDER`. No code changes are needed.

To switch to Azure OpenAI:

```env
LLM_PROVIDER=azure
AZURE_OPENAI_ENDPOINT=https://your-endpoint.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT_CHAT=your-deployment-name
```

To switch back to Gemini:

```env
LLM_PROVIDER=gemini
GEMINI_API_KEY=your-gemini-api-key
```

Restart the reasoning agent after changing `LLM_PROVIDER`.

### API health works but `/v1/assessments` returns `404`

The assessment API route is not wired into the FastAPI app. Fix the router
wiring in code, restart the API, and rerun Part 23.

### Protected API calls return `401`

First check whether `API_AUTH_MODE=development` is set. In development mode the
API never returns `401` — if it does, the setting did not take effect. Verify
`.env` contains `API_AUTH_MODE=development` and restart the API.

If `API_AUTH_MODE=entra`, common causes:

- `Authorization` header is missing.
- `$TOKEN` is empty.
- `JWT_AUDIENCE` in `.env` does not match the app registration URI.
- `AZURE_TENANT_ID` in `.env` does not match your Azure tenant.

Get a new token:

```powershell
$TOKEN = az account get-access-token --resource $JWT_AUDIENCE --query accessToken -o tsv
```

### Protected API calls return `403`

If `API_AUTH_MODE=development`, `403` should not occur because the synthetic
identity has `PLATFORM_ADMIN` role. If it does appear, check route-level RBAC
logic in the codebase.

If `API_AUTH_MODE=entra`, your token probably does not contain a valid WAF Agent
role. Go back to Part 6 and assign your user:

```text
WafAgent Tenant Admin
```

Then get a new token.

### API says it cannot resolve tenant

Check the local tenant row:

```powershell
docker exec wafagent-postgres psql -U wafagent -d wafagent -c "SELECT id, slug, azure_tenant_id, is_active FROM tenants;"
```

The `azure_tenant_id` must match:

```powershell
az account show --query tenantId -o tsv
```

### Agent cannot read Key Vault secret

Check the secret:

```powershell
az keyvault secret show --vault-name $KV --name demo-subscription-reader --query name -o tsv
```

Check your user policy:

```powershell
az keyvault set-policy --name $KV --object-id $USER_OBJECT_ID --secret-permissions get list set
```

### Agent cannot use Service Bus

Check the namespace:

```powershell
az servicebus namespace show --resource-group $RG --name $SB --query serviceBusEndpoint -o tsv
```

Check that `.env` uses:

```env
SERVICEBUS_NAMESPACE=sb-waf-<suffix>.servicebus.windows.net
```

Check your role:

```powershell
az role assignment list --assignee $USER_OBJECT_ID --scope $SB_ID -o table
```

### Report upload fails

Check:

- `STORAGE_ACCOUNT_NAME` is only the storage account name, not a URL.
- The `reports` container exists.
- Your user has `Storage Blob Data Contributor`.

### No findings appear

Check:

```powershell
docker exec wafagent-postgres psql -U wafagent -d wafagent -c "SELECT COUNT(*) FROM waf_rules WHERE is_active = true;"
docker exec wafagent-postgres psql -U wafagent -d wafagent -c "SELECT COUNT(*) FROM assessment_resources;"
docker exec wafagent-postgres psql -U wafagent -d wafagent -c "SELECT COUNT(*) FROM assessment_findings;"
```

If rules and resources exist but findings are zero, the reviewed resources may
be passing the seeded rules. Add more WAF rules for deeper coverage.

### Readiness check shows `redis: unreachable`

Start Redis:

```powershell
docker compose -f docker-compose.dev.yml up -d redis
```

## Command Cheat Sheet

Use this only after reading the full guide once.

```powershell
# Open project folder, then activate Python
.\.venv\Scripts\Activate.ps1

# Start local database and Redis
docker compose -f docker-compose.dev.yml up -d postgres redis

# Run database migrations
alembic upgrade head

# Start API
uvicorn waf_api.main:app --host 0.0.0.0 --port 8000 --reload

# Start agents in separate terminals
python -m waf_preparation.main
python -m waf_extraction.main
python -m waf_reasoning.main
python -m waf_reporting.main

# Health checks
Invoke-RestMethod http://localhost:8000/healthz
Invoke-RestMethod http://localhost:8000/readyz

# Get API token (Entra mode only — skip when API_AUTH_MODE=development)
$TOKEN = az account get-access-token --resource $JWT_AUDIENCE --query accessToken -o tsv

# Run tests
pytest tests/unit -v
pytest tests/integration -v

# Stop local Docker services
docker compose -f docker-compose.dev.yml stop
```

## Official Links

- [Azure CLI install](https://learn.microsoft.com/cli/azure/install-azure-cli)
- [Azure CLI sign-in](https://learn.microsoft.com/cli/azure/authenticate-azure-cli-interactively)
- [Docker Desktop](https://docs.docker.com/desktop/)
- [Docker Compose](https://docs.docker.com/compose/)
- [Gemini API key](https://aistudio.google.com/app/apikey)
- [Gemini pricing](https://ai.google.dev/pricing)
- [Azure Key Vault quickstart](https://learn.microsoft.com/azure/key-vault/secrets/quick-create-cli)
- [Azure Storage account setup](https://learn.microsoft.com/azure/storage/common/storage-account-create)
- [Azure Service Bus queues](https://learn.microsoft.com/azure/service-bus-messaging/service-bus-quickstart-cli)
- [Azure OpenAI (enterprise path)](https://learn.microsoft.com/azure/ai-foundry/openai/how-to/create-resource)
