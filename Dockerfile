FROM python:3.12-alpine@sha256:4c47124a8391cb7a9f571164147d154777cf012a4ece5f86097130d7a4478111

RUN addgroup -g 65534 sandbox 2>/dev/null || true \
    && adduser -D -H -u 65534 -G sandbox sandbox 2>/dev/null || true

WORKDIR /workspace
