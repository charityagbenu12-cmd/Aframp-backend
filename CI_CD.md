# CI/CD Pipeline

This document describes every workflow in `.github/workflows/ci-cd.yml`, the
secrets it requires, and the procedures for staging and production deployments.

---

## Workflow Triggers

| Event | Workflows triggered |
|---|---|
| Pull request targeting `develop` | `check-target`, `changes`, `fmt`, `clippy`, `unit-tests`, `openapi-check`, `validate-gateway-config`, `security-scan`, `integration-tests` |
| Push to `main` | All PR jobs + `build-push`, `deploy-staging` |
| `workflow_dispatch` (manual) | `deploy-production` (requires `version_tag` input) |

> Pull requests targeting `main` directly are rejected by the `check-target`
> job. All changes must flow through `develop` first.

---

## Jobs

### `fmt` — Formatting
Runs `cargo fmt --all -- --check`. Any formatting violation fails the build.

### `clippy` — Linting
Runs `cargo clippy --all-targets --all-features -- -D warnings`. All clippy
warnings are treated as errors.

### `unit-tests` — Unit Tests & Coverage
- Runs `cargo llvm-cov` to execute the unit test suite and generate an LCOV
  coverage report.
- Enforces a minimum coverage threshold defined by the `COVERAGE_THRESHOLD`
  environment variable (default: **60%**).
- Uploads the LCOV report as a build artifact.

### `openapi-check` — OpenAPI Schema Drift
Generates the OpenAPI schema from source and compares it against
`docs/openapi.json`. If the schema has changed but the `info.version` field
has not been bumped, the build fails.

### `validate-gateway-config` — Nginx Validation
Validates the nginx configuration file for required security directives (TLS
version, HSTS, OCSP stapling, etc.).

### `security-scan` — Dependency Audit
Runs `cargo audit` against the advisory database. Any known vulnerability
fails the build.

### `integration-tests` — Integration Tests
Spins up ephemeral **Postgres 16** and **Redis 7** service containers, runs
all database migrations via `sqlx migrate run`, then executes the full
integration test suite.

### `build-push` — Docker Image
Triggered only on pushes to `main` after all quality gates pass.
- Builds a multi-platform image (`linux/amd64`, `linux/arm64`).
- Tags the image with the commit SHA and `latest`.
- Pushes to GitHub Container Registry (`ghcr.io`).
- Scans the image with Trivy and uploads results to GitHub Security.
- Build cache is stored in GitHub Actions cache to minimise repeat build times.

### `deploy-staging` — Staging Deployment
Triggered automatically after a successful `build-push`.
1. Deploys the new image to the staging environment.
2. Runs database migrations against the staging database.
3. Runs post-deployment smoke tests.
4. Notifies the engineering team via Slack regardless of outcome.

### `deploy-production` — Production Deployment
Triggered **manually** via `workflow_dispatch` with a required `version_tag`
input (e.g. `v1.2.3`). Requires explicit reviewer approval configured in the
`production` GitHub environment.
1. Deploys the specified image tag to production.
2. Runs database migrations against the production database.
3. Runs post-deployment smoke tests.
4. **Automatically rolls back** to the previous image tag if smoke tests fail.
5. Notifies the engineering team via Slack regardless of outcome.

---

## Required Secrets

All secrets are stored as encrypted GitHub repository or environment secrets.
No secret is ever logged or echoed in workflow output.

### Repository-level secrets (all environments)

| Secret | Purpose |
|---|---|
| `SLACK_WEBHOOK_URL` | Slack incoming webhook for deployment notifications |

### `staging` environment secrets

| Secret | Purpose |
|---|---|
| `STAGING_HOST` | Hostname / IP of the staging server |
| `STAGING_SSH_KEY` | Private SSH key for staging deployment user |
| `STAGING_DATABASE_URL` | PostgreSQL connection string for staging |

### `production` environment secrets

| Secret | Purpose |
|---|---|
| `PROD_HOST` | Hostname / IP of the production server |
| `PROD_SSH_KEY` | Private SSH key for production deployment user |
| `PROD_DATABASE_URL` | PostgreSQL connection string for production |
| `PROD_PREVIOUS_IMAGE_TAG` | Image tag to roll back to if smoke tests fail |

> `GITHUB_TOKEN` is automatically provided by GitHub Actions and is used for
> pushing images to GHCR. No manual configuration is required.

---

## Deployment Procedures

### Staging (automatic)
Every merge to `main` automatically triggers a staging deployment after the
Docker image is built and pushed. No manual action is required.

### Production (manual)
1. Identify the image tag to deploy (e.g. the commit SHA or a semver tag).
2. Navigate to **Actions → CI/CD Pipeline → Run workflow**.
3. Enter the `version_tag` (e.g. `sha-abc1234` or `v1.2.3`).
4. A configured reviewer must approve the deployment in the `production`
   environment before the job proceeds.
5. Monitor the workflow run for smoke test results and Slack notifications.

### Rollback
If the post-deployment smoke tests fail in production, the pipeline
automatically re-deploys the image tag stored in `PROD_PREVIOUS_IMAGE_TAG`.
To trigger a manual rollback, re-run the `deploy-production` workflow with the
previous tag as the `version_tag` input.

---

## Rust Dependency Caching

All jobs that compile Rust code use `actions/cache@v4` to cache:
- `~/.cargo/registry` — downloaded crate sources
- `~/.cargo/git` — git-sourced crates
- `target/` — compiled build artifacts

The cache key is derived from `Cargo.lock` so it is invalidated automatically
when dependencies change.
