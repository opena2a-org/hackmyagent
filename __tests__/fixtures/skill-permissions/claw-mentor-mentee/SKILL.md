---
name: claw-mentor-mentee
description: Safe OpenClaw evolution — get safety-checked compatibility reports from expert builders delivered directly to your agent. Apply or skip updates, with automatic rollback protection.
metadata: {"openclaw": {"emoji": "🔥", "primaryEnv": "CLAW_MENTOR_API_KEY", "homepage": "https://clawmentor.ai"}}
---

# Claw Mentor — Mentee Skill

> Bring your mentor's updates directly into your OpenClaw agent. Get notified when a new compatibility report is ready, review it in plain English, and apply or skip — all from your OpenClaw chat.

---

## Description

Claw Mentor is a mentorship platform for OpenClaw users. You subscribe to an expert mentor (like Ember 🔥) who maintains a carefully crafted OpenClaw setup. Whenever they update their configuration, you get a plain-English compatibility report explaining what changed, what it does, and whether it's safe for your setup.

This skill connects your local OpenClaw agent to Claw Mentor. Your agent checks for new reports on a schedule, notifies you, and helps you apply or skip changes — including taking a local backup before anything changes.

**Privacy note:** Your AGENTS.md, skill files, and config are NEVER sent to Claw Mentor. The server only receives your onboarding survey answers (which you provide voluntarily) and your apply/skip/rollback decisions. No raw configuration data ever leaves your machine.

---

## What It Does

- Checks `app.clawmentor.ai` every few hours for new compatibility reports from your subscribed mentors
- Notifies you via your configured channel (Telegram, etc.) when a new report is ready
- Shows a plain-English summary: what changed, risk level, what to expect
- Guides you through applying or skipping each update
- Takes a local snapshot (`cp -r`) before any changes, so you can always roll back
- Reports your decision (applied/skipped/rolled back) back to Claw Mentor — no config content shared

---

## Installation

```bash
clawhub install claw-mentor-mentee
```

Start a new OpenClaw session after installing. Your agent will guide you through the API key setup on first use.

Get your API key at: **app.clawmentor.ai → Settings → Mentee Skill**

---

## Setup (First Run)

**When this skill loads, check if `CLAW_MENTOR_API_KEY` is set in your environment.**

**If it IS set:** You're connected. Do a first check immediately by calling `GET https://app.clawmentor.ai/api/mentee/reports` and report back what's waiting. Then ensure `HEARTBEAT.md` in your workspace contains the line `- Check for new Claw Mentor reports` — add it if missing, so periodic checks are scheduled.

**If it is NOT set**, tell the user:

> "To activate ClawMentor, I need your API key.
> 
> 👉 Get it at **app.clawmentor.ai → Settings → Mentee Skill → Generate API Key**
> 
> Once you have it, share it here and I'll configure it."

**When the user provides their API key:**
1. Store it: `openclaw config set 'skills.entries["claw-mentor-mentee"].apiKey' THEIR_KEY`
2. Confirm: "✅ ClawMentor is connected. I'll check for new reports every `CLAW_MENTOR_CHECK_INTERVAL_HOURS` hours (default: 6)."
3. Do a first check immediately — call `GET https://app.clawmentor.ai/api/mentee/reports` and tell them what's waiting.
4. **Schedule periodic checks** — append this line to `HEARTBEAT.md` in your workspace (create the file if it doesn't exist):
   ```
   - Check for new Claw Mentor reports
   ```
   This tells your OpenClaw agent to run the mentee skill check on every heartbeat cycle. Confirm to the user: "✅ Heartbeat check scheduled — I'll ping you automatically when a new report is ready."

---

## Configuration

| Variable | Where it comes from | Default |
|---|---|---|
| `CLAW_MENTOR_API_KEY` | app.clawmentor.ai → Settings → Mentee Skill | Required |
| `CLAW_MENTOR_CHECK_INTERVAL_HOURS` | Optional — set in your OpenClaw environment | `6` |

OpenClaw stores your API key in `~/.openclaw/openclaw.json` under `skills.entries["claw-mentor-mentee"].apiKey` and automatically injects it as `CLAW_MENTOR_API_KEY` each session.

---

## Permissions

| Permission | Why |
|---|---|
| `READ: ~/.openclaw/` | To take snapshots before applying changes |
| `WRITE: ~/.openclaw/claw-mentor/snapshots/` | To store local backup snapshots |
| `WRITE: ~/.openclaw/claw-mentor/state.json` | To track last check time and notified reports |
| `NETWORK: app.clawmentor.ai` | To fetch reports and send status updates |
| `NOTIFY: configured channel` | To alert you when a new report is ready |
| `EXEC: cp, mkdir` | Shell commands for taking snapshots |

No other files are read. No config content is ever uploaded.

---

## Agent Instructions

When this skill is installed, your agent should follow these instructions:

### Heartbeat Check (every `CLAW_MENTOR_CHECK_INTERVAL_HOURS` hours)

1. Read `~/.openclaw/claw-mentor/state.json` to get `last_check` and `notified_report_ids` (create file if absent)
2. If time since `last_check` < `CLAW_MENTOR_CHECK_INTERVAL_HOURS` hours → skip, return `HEARTBEAT_OK`
3. Call `GET https://app.clawmentor.ai/api/mentee/reports` with header `Authorization: Bearer {CLAW_MENTOR_API_KEY}`
4. Update `state.json` with `last_check: now`
5. For each report in the response where `status == 'pending'` AND `id` NOT in `notified_report_ids`:
   - Send a notification message (see format below)
   - Add the report ID to `notified_report_ids` in state
6. If no pending reports → return `HEARTBEAT_OK`

**Notification message format:**
```
🔥 New mentor update ready!

**{mentor_name}** · {risk_emoji} {risk_level_display} risk

{plain_english_summary}

Say **"show my mentor report"** to see the full details.
Or: **"apply mentor report"** / **"skip mentor report"**
```

Risk emoji: LOW → 🟢, MEDIUM → 🟡, HIGH → 🔴

### Command: "show my mentor report" / "my mentor reports" / "check my reports"

1. Call `GET https://app.clawmentor.ai/api/mentee/reports`
2. If no pending reports: "No new mentor reports. You're up to date! ✅"
3. For each pending report, show:
   ```
   📋 Report from {mentor_name} — {date}
   Risk: {risk_level} {risk_emoji}
   
   {plain_english_summary}
   
   Changes:
   • Add: {skill names joined with comma, or "none"}
   • Modify: {skill names, or "none"}  
   • Remove: {skill names, or "none"}
   
   Say "apply mentor report" to apply or "skip mentor report" to skip.
   ```

### Command: "apply mentor report" / "apply [mentor name]'s update"

This is the most important command. Follow all steps carefully.

1. Call `GET https://app.clawmentor.ai/api/mentee/reports` to get the latest pending report
2. If no pending reports: "Nothing to apply — no pending reports."
3. Show the full changes list from the report
4. **Take a snapshot before anything else:**
   ```bash
   SNAPSHOT_DATE=$(date +%Y-%m-%d-%H-%M)
   SNAPSHOT_PATH="$HOME/.openclaw/claw-mentor/snapshots/$SNAPSHOT_DATE/"
   mkdir -p "$SNAPSHOT_PATH"
   cp -r "$HOME/.openclaw/" "$SNAPSHOT_PATH"
   ```
5. Confirm snapshot: "✅ Backup saved to `~/.openclaw/claw-mentor/snapshots/{date}/`"
6. Walk the user through each change as a checklist — show each skill/permission change and ask them to make the change manually in their skills/ directory
7. When user confirms they're done: call `POST https://app.clawmentor.ai/api/mentee/status` with:
   ```json
   { "reportId": "{id}", "status": "applied", "snapshotPath": "{SNAPSHOT_PATH}" }
   ```
8. Confirm: "✅ Marked as applied! Your adoption history is updated on Claw Mentor."

### Command: "skip mentor report" / "skip [mentor]'s update"

1. Get the latest pending report (same API call)
2. If none: "Nothing to skip."
3. Call `POST https://app.clawmentor.ai/api/mentee/status` with `{ "reportId": "{id}", "status": "skipped" }`
4. Confirm: "Skipped. You can still view it at app.clawmentor.ai/dashboard whenever you're ready."

### Command: "roll back [mentor]'s update" / "undo mentor changes"

1. Find the most recently applied report from the last API call (or ask user which one)
2. Check if a snapshot was taken (look in `~/.openclaw/claw-mentor/snapshots/` for the most recent)
3. Show the restore command:
   ```bash
   cp -r ~/.openclaw/claw-mentor/snapshots/{most-recent-date}/ ~/.openclaw/
   ```
4. Remind user: "After restoring, restart your OpenClaw agent for changes to take effect."
5. When user confirms they've restored: call `POST https://app.clawmentor.ai/api/mentee/status` with `{ "reportId": "{id}", "status": "rolled_back" }`

---

## State File Format

`~/.openclaw/claw-mentor/state.json`:
```json
{
  "last_check": "2026-03-01T14:32:00Z",
  "notified_report_ids": ["uuid1", "uuid2"],
  "last_snapshot_path": "~/.openclaw/claw-mentor/snapshots/2026-03-01-14-32/"
}
```

Create this file on first use if it doesn't exist.

---

## API Reference

All endpoints at `https://app.clawmentor.ai`.

### GET /api/mentee/reports
**Auth:** `Authorization: Bearer {CLAW_MENTOR_API_KEY}`  
**Returns:**
```json
{
  "user": { "id": "...", "email": "...", "tier": "starter" },
  "reports": [
    {
      "id": "uuid",
      "created_at": "2026-03-01T10:00:00Z",
      "risk_level": "low",
      "plain_english_summary": "...",
      "skills_to_add": [{ "name": "...", "what_it_does": "...", "permissions_it_needs": [] }],
      "skills_to_modify": [],
      "skills_to_remove": [],
      "permission_changes": [],
      "status": "pending",
      "mentors": { "name": "Ember 🔥", "handle": "ember", "specialty": "..." }
    }
  ],
  "subscriptions": [...]
}
```

### POST /api/mentee/status
**Auth:** `Authorization: Bearer {CLAW_MENTOR_API_KEY}`  
**Body:** `{ "reportId": "uuid", "status": "applied|skipped|rolled_back", "snapshotPath": "~/.openclaw/..." }`  
**Returns:** `{ "success": true, "reportId": "...", "status": "applied", "updated_at": "..." }`

---

## Troubleshooting

**`clawhub install` rate limited** → ClawHub enforces per-IP download limits. Wait 2–3 minutes and retry. If the skill folder already exists from a failed attempt, run `clawhub install claw-mentor-mentee --force` to overwrite it.

**"Invalid API key"** → Go to app.clawmentor.ai → Settings → Mentee Skill → Generate a new key.

**"No reports found"** → Either no reports have been generated yet, or all are already applied/skipped. Claw Mentor runs daily — new reports appear within 24 hours of a mentor update.

**Snapshot failed** → Ensure your OpenClaw agent has filesystem access to `~/.openclaw/`. Check that `cp` and `mkdir` are available in your environment.

**Report not updating** → Check your API key is correct and you have an active subscription at app.clawmentor.ai.

---

## Source

Open source (auditable): [github.com/clawmentor/claw-mentor-mentee](https://github.com/clawmentor/claw-mentor-mentee)

Questions or issues? Open a GitHub issue or email hello@clawmentor.ai.
