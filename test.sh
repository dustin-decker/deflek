#!/bin/sh

set -e

CGO_ENABLED=0 GOOS=`go env GOHOSTOS` GOARCH=`go env GOHOSTARCH` go build -o app
docker build -t deflek -f Dockerfile.local .
docker run -it --rm -v /:/host deflek
