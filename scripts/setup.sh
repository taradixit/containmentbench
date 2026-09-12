#!/bin/sh
set -eu

if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required." >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "Docker is installed, but its daemon is not running." >&2
    exit 1
fi

docker build -t containmentbench:local .
python3 -m unittest discover -s tests -v

