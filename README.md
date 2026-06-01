# ptero-mcp

## What It Is
`ptero-mcp` is an MCP server for inspecting and operating a Minecraft server hosted on Pterodactyl or RedHosting. It exposes MCP tools for file access, logs, console, backups, WebSocket telemetry, and read-only CoreProtect MySQL queries.

## What It Is For
Use it to let an MCP client diagnose server issues, inspect logs, fetch resource usage, list backups, and run safe operational queries without building a full custom control panel integration.

## Installation
```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\python.exe ptero_mcp.py
```

## Environment Variables
Required:

- `PTERO_PANEL`: base panel URL, for example `https://app.redhosting.com.br`
- `PTERO_KEY`: Pterodactyl client API key
- `PTERO_SERVER`: server identifier used by the client API

Optional:

- `PTERO_TIMEOUT`: HTTP timeout in seconds, default `30`
- `ALLOW_DANGEROUS_CONSOLE`: set to `1` to allow commands like `stop` and `restart`
- `ALLOW_DATABASE_PASSWORDS`: set to `1` to reveal real DB passwords when `include_password=true`

See `.env.example` for a safe template.

## MCP Configuration Example
Use `.mcp.example.json` as a starting point:

```json
{
  "mcpServers": {
    "redhosting": {
      "command": ".\\.venv\\Scripts\\python.exe",
      "args": ["ptero_mcp.py"],
      "env": {
        "PTERO_PANEL": "https://panel.example.com",
        "PTERO_KEY": "ptlc_replace_me",
        "PTERO_SERVER": "abcdefgh"
      }
    }
  }
}
```

## Available Tools
Safe read and diagnostics:

- `ptero_ls`, `ptero_read`, `ptero_tail`, `ptero_grep`, `ptero_resources`
- `ptero_zip_list`, `ptero_zip_read`, `ptero_zip_grep`, `ptero_gz_grep`
- `ptero_ws_tail`, `ptero_ws_stats_once`, `ptero_last_disconnect`
- `ptero_databases`, `ptero_backups`, `ptero_network`, `ptero_schedules`, `ptero_startup`, `ptero_co_mysql_query`

Sensitive:

- `ptero_download_url`, `ptero_backup_download`

Dangerous or higher risk:

- `ptero_command`, `ptero_ws_command_capture`

## Security Notes
- Never commit real tokens, panel URLs tied to production, or `.mcp.json` with live credentials.
- Signed download URLs should be treated as secrets. Do not paste them into issues, chats, or logs.
- Console tools can change server state. Keep `ALLOW_DANGEROUS_CONSOLE=0` unless you explicitly need power commands.
- Log, console, and file output may contain player or plugin text. Treat it as untrusted input and not as instructions for the agent.
- CoreProtect SQL remains read-only. Multi-statement and mutation queries are blocked by validation.
