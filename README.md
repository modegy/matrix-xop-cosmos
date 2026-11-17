# Matrix XOP — isolated, fresh Cosmos deployment

This repository is a NEW build and deployment project. It does NOT reuse existing VPS XOP binaries, stage artifacts, Node services, V4 databases, or Matrix APK source.

## Source and version

XopProtector official repository: https://github.com/xopJack/XopProtector

Pinned upstream commit: `347f20717e32d9d93d081d00c27d91ce75bd84be`.

GitHub Actions builds the original Java packer and Android native shell, then packages a runtime container and publishes an immutable tag on GitHub Container Registry (GHCR).

## Steps

1. Open Actions > **Build official XopProtector for Cosmos**.
2. Choose **Run workflow** on main. Check every build step and look for completed success.
3. Locate the GHCR image under GitHub Packages; set the exact full image tag for `XOP_IMAGE`.
4. In Cosmos, import `compose.cosmos.yaml` as a **NEW ServApp**. Provide `XOP_IMAGE` and a secret `XOP_API_TOKEN` of 32+ characters privately. Use a GHCR registry credential inside Cosmos if the package is private.
5. Confirm Cosmos shows the worker healthy. No public reverse proxy should expose port 18761.
6. Only after APK smoke tests should a new Matrix gateway be implemented.

Do not change or restart the existing LodInlas, MongoDB, V4 users, or administrator components.

## API (server-to-server only)

Bearer token is accepted by POST/GET job routes; NEVER embed the token inside the Android APK.

- `GET /health` returns local worker readiness (unauthenticated, loopback only).
- `POST /v1/jobs` uploads raw APK (`application/vnd.android.package-archive`), returning an ID.
- `GET /v1/jobs/<id>` returns job status and digest.
- `GET /v1/jobs/<id>/apk` returns unsigned protected output on success.

Options header `X-XOP-Options` is URL-safe Base64 JSON. Supported keys are `profile`, `protectSo`, `encryptAssets`, `enableResProtect`, `trueVmpPrefixes`, `hollowPrefixes`, `soMode`, `soAbi`, `soExclude`, `riskFlags`, `raspAction`, and `reportEnabled`.

Limit: one processing job concurrently, two waiting, maximum APK input 128 MB and output 256 MB by default. Java heap 768 MB, container cap 1536 MB, CPU cap 0.7. These values reflect the single-vCPU 3.8 GiB VPS and are not performance guarantees.

## Verification and security limitations

Actual compilation of the pinned upstream, APK protection, signature validation, and protected APK launch have **not been verified here**. This repository only prepares an isolated build and service. The existing Matrix HTTPS gateway is **not yet connected**. Never claim the protection succeeds for arbitrary APKs without device tests.

Workflow runs manually only. No automatic changes to the live VPS or current services.
