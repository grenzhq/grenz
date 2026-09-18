# Grenz Console

A local dashboard over the Grenz proxy's loopback admin API: live requests and
the verdict on each, approvals you can answer in one click, a **Firewall
Activity** feed naming each defense the proxy fires (tripwire, taint-flow,
session pin, decoy, DLP, kill-switch, …), a form-based **Policy editor**, and
an **Access** screen for the kill-switch and temporary grants.

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

## How it's put together

Next.js App Router, Tailwind v4, and [shadcn/ui](https://ui.shadcn.com)
components vendored under `components/ui/` (the `radix-nova` style: Radix
primitives, Lucide icons, Geist). Charts are Recharts through shadcn's chart
wrapper.

| Path | What lives there |
|---|---|
| `app/layout.tsx` | The shell: sidebar, header, one data provider |
| `app/*/page.tsx` | One screen per sidebar entry |
| `app/api/*` | Server routes that forward to the proxy with the admin token |
| `components/console-data.tsx` | The single poller; every screen reads it |
| `components/ui/*` | Vendored shadcn components — regenerate, don't hand-edit |
| `lib/types.ts` | Shapes the admin API returns |
| `lib/grenz.ts` | Token handling and proxy forwarding (server-only) |

Two conventions worth keeping:

- **One poller.** `ConsoleDataProvider` polls the admin API once per interval
  and shares the snapshot through context. Adding a `fetch` inside a screen
  multiplies load on the proxy for no benefit — add the endpoint to the
  provider instead. It also pauses while the tab is hidden.
- **Decisions have their own colour tokens.** `allow` / `deny` / `held` /
  `tripwire` in `app/globals.css` are separate from `primary` and
  `destructive`, so changing the brand colour can never repaint a verdict. Use
  `<DecisionBadge>` rather than restyling a badge inline.

Dark and light are both designed; the theme follows the system by default and
the header toggle overrides it (stored in `localStorage`, applied before first
paint by a small inline script — there is no theme library).

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
