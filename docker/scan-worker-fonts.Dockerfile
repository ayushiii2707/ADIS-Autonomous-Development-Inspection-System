# Adds an emoji font to the security-audit-pipeline worker image.
#
# The worker renders its PDF report with Chrome, and the upstream image ships only
# the DejaVu and Liberation fonts, which have no emoji glyphs. The report uses ✅ ❌
# and similar marks (scanner coverage tables, "Fixed ✅" badges), which otherwise
# print as empty boxes. Built by `npm run scan-worker:build` on top of the pipeline image.

ARG BASE_IMAGE=security-audit-worker-base
FROM ${BASE_IMAGE}
USER root
RUN apt-get update \
  && apt-get install -y --no-install-recommends fonts-noto-color-emoji \
  && rm -rf /var/lib/apt/lists/* \
  && fc-cache -f
USER worker
