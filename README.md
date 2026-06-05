# NetScope

NetScope is a lightweight reconnaissance and scanning toolkit written in Go. The project includes:

- a core scanning library and utilities for TCP/UDP scans, banner grabbing, and SSL certificate extraction;
- an HTTP API server that exposes scanning endpoints;
- a small single-page web UI (Vue 3 + Tailwind via CDN) to run scans and view results.

This README provides build/run instructions, API documentation, development notes and recommended next steps.

Key source files

- `main.go` — program entrypoint and mode dispatch (TUI / CLI / web)
- `server.go` — HTTP server and API handlers
- `scanner.go` — core scanning logic
- `web/` — static SPA assets ([web/index.html](web/index.html), [web/app.js](web/app.js), [web/style.css](web/style.css))


## Prerequisites

- Go 1.20+ installed and configured (uses Go modules)
- Docker & Docker Compose (optional, recommended for container runs)


## Build and run (local)

1. Clone the repository and build the binary:

```bash
git clone <repo-url>
cd NetScope
go build -o scanner_web .
```

2. (Optional) Configure an API key for the HTTP API. If set, the API will require the key on all `/api/*` requests. Use either `Authorization: Bearer <key>` or `X-API-Key: <key>`.

```bash
export SCANNER_API_KEY=your-secret
```

3. Start the web server (default address `:8080`):

```bash
SCANNER_API_KEY=your-secret ./scanner_web web :8080
```

Open `http://localhost:8080` in a browser.


## Docker Compose

A minimal `docker-compose.yml` has been included for convenience. It builds the application and runs it in `web` mode.

```bash
# Build and start the service
SCANNER_API_KEY=your-secret docker compose up --build

# Stop and remove
docker compose down
```

If your environment uses the legacy `docker-compose` binary, replace `docker compose` with `docker-compose` in the commands above.

### Single-command Docker launch

Run this helper script to build the image, start the container, and open the web UI in your default browser:

```bash
./docker-up.sh
```

If you want to provide a custom API key, use:

```bash
SCANNER_API_KEY=your-secret ./docker-up.sh
```

The script launches the service in detached mode and opens `http://localhost:8080` automatically.


## HTTP API endpoints

All endpoints are JSON-based and available under `/api/`.

- GET `/api/scan/local?concurrency=N`
	- Run a local network scan with optional concurrency (integer). Returns discovered hosts and counts.

- GET `/api/scan/asn?asn=AS12345&concurrency=N`
	- Run a scan against prefixes announced by the provided ASN.

- GET `/api/reverse?ip=1.2.3.4`
	- Reverse DNS lookup for the given IP. Returns `names: []`.

- GET `/api/ssl?host=example.com&port=443`
	- Retrieve SSL certificate information for `host:port`.

- GET `/api/custom?ip=1.2.3.4&ports=22,80,443`
	- Scan the listed ports for the given IP.

Implementation details live in [server.go](server.go).


## Authentication and CORS

- If the environment variable `SCANNER_API_KEY` is set, API calls must include either `Authorization: Bearer <key>` or header `X-API-Key: <key>`.
- The server currently sets permissive CORS (`Access-Control-Allow-Origin: *`) to make local development easy. Adjust `setCORS` in [server.go](server.go) to restrict allowed origins.


## Web UI

- The web UI is a lightweight Vue 3 SPA mounted at `/` and implemented in [web/index.html](web/index.html) + [web/app.js](web/app.js).
- Tailwind CSS is loaded via the Play CDN for rapid prototyping. For production, switch to a build-time Tailwind pipeline to purge unused CSS.


## Development notes

- Frontend quick-start: The UI uses CDN assets so no frontend build step is required for development.
- If you prefer a production-ready frontend, add `package.json` and set up a small toolchain:
	- Install `tailwindcss`, `postcss`, and a bundler (Vite/webpack).
	- Create `tailwind.config.js` and build `web/style.css` during CI or container image build.


## Testing

Run Go tests with:

```bash
go test ./...
```


## Next steps (suggested)

- Harden API auth: use JWTs or OAuth for multi-user access control.
- Add backend persistence for scan history (SQLite, BoltDB or Postgres).
- Wire Vue Router and a history view to the SPA for saved scans.
- Add Prometheus metrics endpoint and basic dashboard.
- Replace Tailwind CDN with a compiled CSS pipeline to optimize bundle size.


## Contributing

Contributions are welcome. Please open issues for bugs or feature requests and provide tests when applicable. Run `go test ./...` before submitting a PR.


If you want, I can implement any of these next steps for you — say which one and I'll get started.
