# Security

## Reporting a vulnerability

Please report security issues privately through GitHub's "Report a vulnerability" (Security tab) rather than a public issue.

## Secrets

- All credentials come from environment variables or a local `.env` file (gitignored). See `.env.example`.
- The app connects to MySQL as a dedicated least-privilege user, never `root`.
- User passwords are hashed with Argon2. There are no default accounts: the first admin is created on the first visit to the dashboard, or with `intrusionsense create-admin`. Passwords must be at least 12 characters.
- In Docker, the database password and session secret are generated at first start into a private volume.
- Sign-in is rate limited per address and username. Sessions use a `SameSite=Strict` cookie, every state-changing request must carry a client header (CSRF), and the WebSocket checks the page's origin.
- Roles (Admin, Manager, SOC Analyst) are checked on the server for every route, and sign-ins and changes are written to an activity log.
- Sensors authenticate with random tokens that are stored hashed and can be revoked in the dashboard.
- The dashboard sends a Content-Security-Policy that blocks inline script and third-party origins; captured request data is shown as plain text.
- The server container runs as a non-root user with a read-only filesystem and no capabilities. The Linux capture container keeps only the raw-socket capability.
- Secret scanning runs on every commit through the gitleaks pre-commit hook (`pre-commit install`).

## Previously committed credential

Early commits contained the password of a local development MySQL `root` account in `src/config.py`. That server is no longer used: the project now runs MySQL in Docker with a generated password, and the app never connects as `root`. If you reused that old value anywhere else, change it there. History was deliberately **not** rewritten: for a secret that no longer protects anything, a rewrite and force-push only breaks existing clones. Rotating a leaked secret is the fix, not deleting it from history.
