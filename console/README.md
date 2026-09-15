# Grenz Console

A minimal local dashboard over the Grenz proxy's loopback admin API: a live
**Firewall Activity** feed that names each defense the proxy fires
(tripwire, taint-flow, session pin, decoy, DLP, kill-switch, …), plus live
requests, allow/deny/approval counts, and one-click approve/deny for pending
requests. A form-based
**Policy editor** (/policy) edits the agent's grants — validated before it's
applied, with advanced sections and comments preserved.

The admin token stays server-side (read from the Grenz home); the browser only
talks to this app's API routes.

## Run

Start the proxy first (`grenz run`), then:

```bash
cd console
bun install          # or npm install
bun run dev          # http://localhost:4180
```

By default the console reads `admin.token` from `../.grenz` and talks to the
proxy at `http://127.0.0.1:8787`. Override with env vars:

| Env | Default | Purpose |
|---|---|---|
| `GRENZ_PROXY_URL` | `http://127.0.0.1:8787` | Where the proxy listens |
| `GRENZ_HOME` | `../.grenz` | Grenz home (to read `admin.token`) |
| `GRENZ_ADMIN_TOKEN` | — | Admin token directly (skips reading the file) |

Example against a proxy on a custom port and home:

```bash
GRENZ_PROXY_URL=http://127.0.0.1:9930 GRENZ_HOME=/path/to/.grenz bun run dev
```

The console never shows credential material — it renders only decision metadata
the proxy exposes.

## Security / trust model

This is a **local, single-user** dashboard. The admin token stays server-side
(it is never sent to the browser), and the console exposes only what the proxy's
admin API exposes.

- It binds to **loopback (`127.0.0.1`)** by default, so it is not reachable from
  the network. Do not change the bind host to a public interface.
- The `/api/*` routes reject **cross-site** browser requests (a CSRF guard), so a
  malicious page you visit cannot drive the console.
- It intentionally trusts **local same-user access** — the same boundary as the
  `0600 admin.token` file, which any process running as you can already read. If
  you need multi-user or remote access, put the console behind your own
  authenticating reverse proxy; do not expose it directly.
