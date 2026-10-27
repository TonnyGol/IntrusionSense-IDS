# Security

## Reporting a vulnerability

Please report security issues privately through GitHub's "Report a vulnerability" (Security tab) rather than a public issue.

## Secrets

- All credentials come from environment variables or a local `.env` file (gitignored). See `.env.example`.
- The app connects to MySQL as a dedicated least-privilege user, never `root`.
- User passwords are hashed with Argon2. There are no default accounts; the first admin is created with `python -m database.create_admin`.
- Secret scanning runs on every commit through the gitleaks pre-commit hook (`pre-commit install`).

## Previously committed credential

Earlier commits contained a local development MySQL `root` password in `src/config.py`. That password has been rotated, so the value in history no longer grants access. History was deliberately **not** rewritten: once a secret is rotated, a rewrite and force-push adds no protection and breaks existing clones. Rotation, not history removal, is the fix for any leaked secret.
