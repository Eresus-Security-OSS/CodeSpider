# Gitea Setup Guide

## 1. Create a Gitea Bot Account
1. Create a dedicated Gitea user (for example, `codespider`).
2. Add this user as a collaborator (or org team member with Read + PR/Issue Write permissions) on repositories you want reviewed.
3. Log in as `codespider` → **Settings → Applications → Generate New Token** (needs `read:repository`, `write:issue`, `write:repository` for commit statuses).
4. Set `gitea.token` and `gitea.bot_username: "codespider"` in your `codespider.yaml`.

## 2. Configure the Webhook
You can configure the webhook per repository (**Repo Settings → Webhooks → Add Webhook → Gitea**) or globally (**Site Administration → Default/System Webhooks**):

- **Target URL:** `http://<codespider-host>:8080/webhook`
- **HTTP Method:** `POST`
- **Content Type:** `application/json`
- **Secret:** Same value as `gitea.webhook_secret` in `codespider.yaml`
- **Trigger On:** Custom Events → check:
  - `Pull Request`
  - `Issue Comment`
  - `Pull Request Comment`

## 3. Run CodeSpider 24/7
```bash
cp codespider.example.yaml codespider.yaml
# Edit codespider.yaml with your Gitea and LLM settings
go run ./cmd/codespider -f codespider.yaml
```

Or build a static binary:
```bash
go build -o codespider ./cmd/codespider
./codespider -f codespider.yaml
```

## 4. Usage
- **Automatic:** Open or push to a PR in Gitea. CodeSpider sets commit status `codespider/review` to `pending`, inspects the diff and repo context, and submits inline comments + a summary.
- **Interactive:** Comment `@codespider <question>` on any PR (or directly inside an inline code review thread), or use slash commands:
  - `@codespider /review` — Force a fresh review on the current commit.
  - `@codespider /redteam` — Run an adversarial Red-Team/Blue-Team security audit.
  - `@codespider /summary` — Generate a structured PR walkthrough.
  - `@codespider /ci` — Diagnose failing CI / commit status checks.
  - `@codespider /fix <instructions>` — Propose (or commit in write mode for collaborators) targeted fixes.
  - `@codespider /help` — Display available commands.
- **One-Shot CLI Mode:** `./codespider review -f codespider.yaml --dry-run owner/repo#12`
- **Health, Metrics, SSE & Playground:** Check `GET /healthz`, `GET /readyz`, `GET /status`, `GET /metrics` (Prometheus), `GET /events` (SSE stream), or open `GET /` (`/dashboard`) for the live UI and Dry-Run Playground. Send `SIGHUP` to hot-reload skills and budgets without restarting.
