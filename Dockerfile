FROM python:3.12-alpine

RUN addgroup -g 65534 sandbox 2>/dev/null || true \
    && adduser -D -H -u 65534 -G sandbox sandbox 2>/dev/null || true

WORKDIR /workspace

