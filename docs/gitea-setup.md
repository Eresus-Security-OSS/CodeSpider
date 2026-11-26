# Gitea Setup Guide

## 1. Create a Gitea Bot Account
1. Create a dedicated Gitea user (for example, `codespider`).
2. Add this user as a collaborator (or org team member with Read + PR/Issue Write permissions) on repositories you want reviewed.
3. Log in as `codespider` → **Settings → Applications → Generate New Token** (needs `read:repository`, `write:issue`, `write:repository` for commit statuses).
4. Set `GITEA_TOKEN` and `GITEA_BOT_USERNAME=codespider` in your `.env`.

## 2. Configure the Webhook
You can configure the webhook per repository (**Repo Settings → Webhooks → Add Webhook → Gitea**) or globally (**Site Administration → Default/System Webhooks**):

- **Target URL:** `http://<codespider-host>:8080/webhook`
- **HTTP Method:** `POST`
- **Content Type:** `application/json`
- **Secret:** Same value as `GITEA_WEBHOOK_SECRET`
- **Trigger On:** Custom Events → check:
  - `Pull Request`
  - `Issue Comment`
  - `Pull Request Comment`

## 3. Run CodeSpider 24/7
```bash
cp .env.example .env
# Edit .env with your Gitea and LLM settings
set -a && source .env && set +a
go run ./cmd/codespider
```

Or build a static binary:
```bash
go build -o codespider ./cmd/codespider
./codespider
```

## 4. Usage
- **Automatic:** Open or push to a PR in Gitea. CodeSpider sets commit status `codespider/review` to `pending`, inspects the diff and repo context, and submits inline comments + a summary.
- **Interactive:** Comment `@codespider <question or request>` on any PR to ask for explanations, security checks, or follow-up analysis.
- **Health & Status:** Check `GET /healthz`, `GET /readyz`, or `GET /status` for active jobs and recent runs.
