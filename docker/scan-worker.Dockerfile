# syntax=docker/dockerfile:1
#
# Security-audit worker image for this app, built natively for linux/amd64 AND linux/arm64.
#
# Why this file exists instead of the pipeline's own apps/security-audit-worker/Dockerfile:
# that one pins linux/amd64 and downloads x86-only binaries. On an Apple-silicon Mac it runs under
# emulation, where `codeql --version` and `opengrep --version` take ~4 s each; the worker's
# readiness check allows 5 s, so the two (launched together) timed out and every scan was refused
# with "binary not found on PATH". Built for the machine's own architecture, the same checks take
# well under a second, and the scans themselves run several times faster.
#
# Everything the upstream image installs is installed here too, at the same pinned versions, with
# the asset picked per architecture. Two exceptions, both forced by what upstream publishes:
#   - CodeQL: the pinned 2.20.3 bundle has no linux-arm64 build (arm64 bundles start later), so both
#     architectures move to the same newer bundle. One version everywhere keeps results comparable.
#   - Chrome for the PDF report: Chrome for Testing (what puppeteer downloads) has no linux-arm64
#     build, so arm64 uses Debian's Chromium. Both are reached through /usr/local/bin/report-chrome.
#
# Build context: the security-audit-pipeline checkout (scan-worker.Dockerfile.dockerignore keeps it
# small). A second named context, `adis`, is this repository's docker/ folder, for the patch:
#   docker buildx build -f docker/scan-worker.Dockerfile --build-context adis=docker \
#     --platform linux/arm64 -t security-audit-worker <pipeline checkout>
# `npm run scan-worker:build` does exactly this for the machine's own architecture.

# ---- Build stage: compile the TypeScript on the BUILD machine's own architecture -------------
# dist/ is plain JavaScript, so it is the same for every target; compiling natively avoids the
# tsc/esbuild crashes that upstream documents under emulation.
FROM --platform=$BUILDPLATFORM node:20-bookworm AS builder
WORKDIR /packages/ai-metering
COPY packages/ai-metering/package.json packages/ai-metering/tsconfig.json packages/ai-metering/tsconfig.build.json ./
RUN npm install --ignore-scripts --no-audit --no-fund
COPY packages/ai-metering/src ./src
COPY packages/ai-metering/contract ./contract
RUN npx tsc -p tsconfig.build.json
WORKDIR /app
COPY apps/security-audit-worker/package.json ./
RUN PUPPETEER_SKIP_DOWNLOAD=true npm install --legacy-peer-deps --no-audit --no-fund
COPY apps/security-audit-worker/tsconfig.json ./
COPY apps/security-audit-worker/src ./src
# Local fixes on top of the pinned pipeline commit (see the patch header for each one).
COPY --from=adis patches/worker-native-arm64.patch /tmp/worker-native-arm64.patch
RUN cd /app && git apply -p3 /tmp/worker-native-arm64.patch \
    && grep -q "One at a time, not in parallel" /app/src/config.ts
# Compiles, then runs the scanner-catalog, scanner-pipeline and secret-redaction selfchecks.
RUN npm run build

# ---- Runtime stage: one image per target architecture ----------------------------------------
FROM node:20-bookworm
ARG TARGETARCH
ARG BUILDARCH

# Same pins as upstream, except CodeQL (see the header).
ARG CODEQL_BUNDLE_TAG=codeql-bundle-v2.27.3
ARG OPENGREP_VERSION=v1.1.0
ARG TRIVY_VERSION=0.74.0
ARG OSV_SCANNER_VERSION=2.6.0
ARG TRUFFLEHOG_VERSION=3.97.5
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_TEMPLATES_VERSION=v10.4.9
ARG SONAR_SCANNER_VERSION=6.2.1.4610
ARG DOTNET_SONARSCANNER_VERSION=6.2.0
ARG DOTNET_CHANNEL=8.0

ENV DEBIAN_FRONTEND=noninteractive \
    PUPPETEER_CACHE_DIR=/opt/puppeteer-cache \
    PUPPETEER_EXECUTABLE_PATH=/usr/local/bin/report-chrome \
    DOTNET_ROOT=/usr/share/dotnet \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    DOTNET_TOOLS_HOME=/opt/dotnet-tools \
    PATH=/opt/codeql:/usr/share/dotnet:/opt/sonar-scanner/bin:/opt/dotnet-tools:$PATH

# Release-asset names per architecture, written once and read by every install step below.
RUN set -eu; case "$TARGETARCH" in \
      amd64) printf '%s\n' ELF_MACHINE=3e00 CODEQL_ASSET=codeql-bundle-linux64.tar.gz OPENGREP_ASSET=opengrep_manylinux_x86 \
               TRIVY_ARCH=64bit GO_ARCH=amd64 SONAR_ARCH=x64 ;; \
      arm64) printf '%s\n' ELF_MACHINE=b700 CODEQL_ASSET=codeql-bundle-linux-arm64.tar.gz OPENGREP_ASSET=opengrep_manylinux_aarch64 \
               TRIVY_ARCH=ARM64 GO_ARCH=arm64 SONAR_ARCH=aarch64 ;; \
      *) echo "Unsupported TARGETARCH: $TARGETARCH (amd64 and arm64 are supported)" >&2; exit 1 ;; \
    esac > /etc/adis-arch.env; \
    # NATIVE=0 when this image is built under emulation (e.g. amd64 on an Apple-silicon Mac). Some
    # tools cannot run there (OpenGrep's bundle under Rosetta; see the upstream Dockerfile), so the
    # checks that EXECUTE them run only on a native build. Structural checks always run.
    if [ "$BUILDARCH" = "$TARGETARCH" ]; then echo NATIVE=1; else echo NATIVE=0; fi >> /etc/adis-arch.env

# ---- System packages: git, JDK (CodeQL Java/Kotlin), unzip/curl, Chrome libraries, fonts ------
# fonts-noto-color-emoji: the PDF report prints ✅/❌ marks, which DejaVu/Liberation cannot draw.
# chromium (arm64 only): the report's browser, since Chrome for Testing has no linux-arm64 build.
RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates curl unzip default-jdk-headless \
      libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 \
      libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 \
      libpango-1.0-0 libcairo2 libatspi2.0-0 fonts-liberation fonts-noto-color-emoji \
      $( [ "$TARGETARCH" = arm64 ] && echo chromium ) \
    && rm -rf /var/lib/apt/lists/* \
    && fc-cache -f

# Checks that a download is a real, complete executable for THIS architecture (not a 404 page, a
# truncated file or the other architecture's asset), then runs it. Built natively, so a binary that
# cannot run fails the build instead of shipping.
RUN printf '%s\n' \
      '#!/bin/sh' \
      'set -eu' \
      '. /etc/adis-arch.env' \
      'bin="$1"' \
      '[ -x "$bin" ] || { echo "MISSING or not executable: $bin" >&2; exit 1; }' \
      '[ "$(od -An -tx1 -N4 "$bin" | tr -d " \n")" = "7f454c46" ] || { echo "NOT an ELF binary: $bin" >&2; exit 1; }' \
      'machine=$(od -An -tx1 -j18 -N2 "$bin" | tr -d " \n")' \
      '[ "$machine" = "$ELF_MACHINE" ] || { echo "WRONG architecture: $bin (e_machine=$machine, want $ELF_MACHINE)" >&2; exit 1; }' \
      '[ "$(wc -c < "$bin")" -gt 1000000 ] || { echo "SUSPICIOUSLY SMALL: $bin" >&2; exit 1; }' \
      'shift' \
      '"$bin" "$@" 2>&1 | head -3' \
    > /usr/local/bin/verify-binary \
    && chmod +x /usr/local/bin/verify-binary

# ---- CodeQL bundle (CLI + the standard query packs the scanner references) -------------------
RUN . /etc/adis-arch.env \
    && curl -fsSL "https://github.com/github/codeql-action/releases/download/${CODEQL_BUNDLE_TAG}/${CODEQL_ASSET}" -o /tmp/codeql.tar.gz \
    && tar -xzf /tmp/codeql.tar.gz -C /opt \
    && rm /tmp/codeql.tar.gz \
    && codeql --version \
    && codeql resolve languages --format=betterjson >/dev/null

# ---- Trivy (dependencies, IaC misconfiguration, secrets, licences) ---------------------------
# The vulnerability database is fetched at scan time, never baked in (a stale DB under-reports).
RUN . /etc/adis-arch.env \
    && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" -o /tmp/trivy.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz \
    && verify-binary /usr/local/bin/trivy --version

# ---- OSV-Scanner (dependency vulnerabilities from osv.dev) -----------------------------------
RUN . /etc/adis-arch.env \
    && curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${GO_ARCH}" -o /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner \
    && verify-binary /usr/local/bin/osv-scanner --version

# ---- TruffleHog (credentials anywhere in git history) -----------------------------------------
RUN . /etc/adis-arch.env \
    && curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${GO_ARCH}.tar.gz" -o /tmp/trufflehog.tar.gz \
    && tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog \
    && rm /tmp/trufflehog.tar.gz \
    && verify-binary /usr/local/bin/trufflehog --version

# ---- Nuclei + pinned templates (external posture scan) ----------------------------------------
RUN . /etc/adis-arch.env \
    && curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${GO_ARCH}.zip" -o /tmp/nuclei.zip \
    && unzip -q -o /tmp/nuclei.zip -d /tmp/nuclei \
    && mv /tmp/nuclei/nuclei /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei.zip /tmp/nuclei \
    && verify-binary /usr/local/bin/nuclei -version

# Read by the worker's nuclei plugin, which passes it with -t so the pinned set is what runs.
ENV NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates
RUN curl -fsSL "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${NUCLEI_TEMPLATES_VERSION}.tar.gz" -o /tmp/nuclei-templates.tar.gz \
    && mkdir -p "${NUCLEI_TEMPLATES_DIR}" \
    && tar -xzf /tmp/nuclei-templates.tar.gz -C "${NUCLEI_TEMPLATES_DIR}" --strip-components=1 \
    && rm /tmp/nuclei-templates.tar.gz \
    && echo "${NUCLEI_TEMPLATES_VERSION}" > "${NUCLEI_TEMPLATES_DIR}/.adis-pinned-version"

# ---- OpenGrep (pattern-based SAST) -----------------------------------------------------------
# Natively, `opengrep --version` works, so it is verified by running it (upstream could not).
RUN . /etc/adis-arch.env \
    && curl -fsSL "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${OPENGREP_ASSET}" -o /usr/local/bin/opengrep \
    && chmod +x /usr/local/bin/opengrep \
    && verify-binary /usr/local/bin/opengrep --version \
    && if [ "$NATIVE" = 1 ]; then opengrep --version; fi

# ---- SonarScanner CLI (bundles its own JRE per architecture) ---------------------------------
RUN . /etc/adis-arch.env \
    && curl -fsSL "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-${SONAR_ARCH}.zip" -o /tmp/sonar.zip \
    && unzip -q /tmp/sonar.zip -d /opt \
    && mv "/opt/sonar-scanner-${SONAR_SCANNER_VERSION}-linux-${SONAR_ARCH}" /opt/sonar-scanner \
    && rm /tmp/sonar.zip \
    && sonar-scanner --version

# ---- .NET SDK (CodeQL runs `dotnet build` for .NET repos); the installer detects the arch ----
RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && bash /tmp/dotnet-install.sh --channel "${DOTNET_CHANNEL}" --runtime dotnet --install-dir "${DOTNET_ROOT}" \
    && rm /tmp/dotnet-install.sh
RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && bash /tmp/dotnet-install.sh --channel "${DOTNET_CHANNEL}" --install-dir "${DOTNET_ROOT}" \
    && rm /tmp/dotnet-install.sh \
    && dotnet --version

# ---- dotnet-sonarscanner (architecture-independent .NET DLLs; same install as upstream) -------
RUN curl -fsSL "https://api.nuget.org/v3-flatcontainer/dotnet-sonarscanner/${DOTNET_SONARSCANNER_VERSION}/dotnet-sonarscanner.${DOTNET_SONARSCANNER_VERSION}.nupkg" -o /tmp/dotnet-sonarscanner.nupkg \
    && mkdir -p "${DOTNET_TOOLS_HOME}" \
    && unzip -q /tmp/dotnet-sonarscanner.nupkg -d /tmp/dotnet-sonarscanner-pkg \
    && cp -r /tmp/dotnet-sonarscanner-pkg/tools/netcoreapp3.1/any/. "${DOTNET_TOOLS_HOME}/" \
    && printf '#!/bin/sh\nexec dotnet "%s/SonarScanner.MSBuild.dll" "$@"\n' "${DOTNET_TOOLS_HOME}" > "${DOTNET_TOOLS_HOME}/dotnet-sonarscanner" \
    && chmod +x "${DOTNET_TOOLS_HOME}/dotnet-sonarscanner" \
    && find "${DOTNET_TOOLS_HOME}" -type f -path '*/bin/sonar-scanner' -exec chmod +x {} + \
    && rm -rf /tmp/dotnet-sonarscanner.nupkg /tmp/dotnet-sonarscanner-pkg \
    && dotnet-sonarscanner 2>&1 | grep -q "Usage on SonarCloud"

WORKDIR /app

# ---- App dependencies (npm picks each native optional dependency for this architecture) -------
COPY --from=builder /packages/ai-metering/package.json /packages/ai-metering/package.json
COPY --from=builder /packages/ai-metering/dist /packages/ai-metering/dist
COPY --from=builder /packages/ai-metering/contract /packages/ai-metering/contract
RUN cd /packages/ai-metering && npm pkg delete scripts.prepare devDependencies
COPY apps/security-audit-worker/package.json ./
RUN PUPPETEER_SKIP_DOWNLOAD=true npm install --legacy-peer-deps --no-audit --no-fund

# ---- The report's browser, at one fixed path on both architectures ---------------------------
# amd64: the Chrome for Testing build puppeteer pins (as upstream). arm64: Debian's Chromium.
RUN set -eu; . /etc/adis-arch.env; \
    if [ "$TARGETARCH" = amd64 ]; then \
      npx puppeteer browsers install chrome; \
      chrome=$(find "$PUPPETEER_CACHE_DIR/chrome" -type f -name chrome -path '*chrome-linux64*' | head -1); \
    else \
      chrome=/usr/bin/chromium; \
    fi; \
    [ -x "$chrome" ] || { echo "Report browser not found" >&2; exit 1; }; \
    printf '#!/bin/sh\nexec "%s" "$@"\n' "$chrome" > /usr/local/bin/report-chrome; \
    chmod +x /usr/local/bin/report-chrome; \
    if [ "$NATIVE" = 1 ]; then report-chrome --headless=new --no-sandbox --disable-gpu --dump-dom about:blank >/dev/null; fi

# ---- Users (same as upstream): `worker` holds the job's secrets; customer builds run as
# `scanbuild`, which cannot read worker's memory or environment.
RUN apt-get update && apt-get install -y --no-install-recommends sudo && rm -rf /var/lib/apt/lists/* \
    && groupadd scan \
    && useradd -m -d /home/worker -s /bin/bash -g scan worker \
    && useradd -m -d /home/scanbuild -s /usr/sbin/nologin -g scan scanbuild \
    && chmod 0700 /home/worker \
    && printf '%s\n' \
         'Defaults:worker !secure_path, !lecture, umask=0002' \
         'worker ALL=(scanbuild) NOPASSWD:SETENV: ALL' > /etc/sudoers.d/scanbuild \
    && chmod 0440 /etc/sudoers.d/scanbuild \
    && visudo -cf /etc/sudoers.d/scanbuild

RUN mkdir -p /home/worker/.config/nuclei \
    && printf '# intentionally empty - template selection is an explicit allowlist\n' > /home/worker/.config/nuclei/.nuclei-ignore \
    && chown -R worker:scan /home/worker/.config

# ---- Compiled app (from the build stage) ------------------------------------------------------
COPY --from=builder /app/dist ./dist

ENV NODE_ENV=production
ENV HOME=/home/worker
ENV SCAN_BUILD_USER=scanbuild
USER worker

# This app runs the worker as an HTTP service (scripts/scan-worker.mjs passes this command too).
CMD ["node", "dist/server.js"]
