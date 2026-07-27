# Docker Image Release

SentinelGuard publishes the gateway container through
`.github/workflows/docker.yml`.

The workflow runs automatically when a GitHub Release is published. It can also
be started manually from GitHub Actions.

## Images

By default, the workflow publishes to GitHub Container Registry:

```text
ghcr.io/<github-owner>/sentinelguard-gateway:<version>
ghcr.io/<github-owner>/sentinelguard-gateway:latest
```

Docker Hub publishing is optional:

```text
<dockerhub-owner>/sentinelguard-gateway:<version>
<dockerhub-owner>/sentinelguard-gateway:latest
```

## Required Settings

For GHCR, no custom secret is required. The workflow uses GitHub's built-in
`GITHUB_TOKEN` with `packages: write` permission.

For Docker Hub, add these repository secrets:

```text
DOCKERHUB_USERNAME
DOCKERHUB_TOKEN
```

Also add this repository variable:

```text
DOCKERHUB_IMAGE=aitechnav/sentinelguard-gateway
```

Use your real Docker Hub namespace instead of `aitechnav` if different.

## SBOM And Signing

An SBOM is a software bill of materials: a machine-readable list of software
components and dependencies in the image. Enterprise security teams use it to
answer questions like "does this image contain a vulnerable package?"

Image signing proves that the pushed image came from the expected GitHub
Actions workflow. The Docker workflow uses keyless cosign signing through
GitHub OIDC, so no signing key secret is required.

The workflow enables:

- Docker Buildx SBOM attestation
- Docker Buildx provenance attestation
- cosign keyless signatures for pushed tags

Example verification after a release:

```bash
cosign verify ghcr.io/aitechnav/sentinelguard-gateway:0.0.10 \
  --certificate-identity-regexp 'https://github.com/.*/.github/workflows/docker.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Example SBOM/provenance inspection:

```bash
docker buildx imagetools inspect ghcr.io/aitechnav/sentinelguard-gateway:0.0.10
```

## Manual Release

Use the `Publish Docker Image` workflow manually with:

```text
version: 0.0.10
branch: main
publish_dockerhub: true
dockerhub_image: aitechnav/sentinelguard-gateway
```
