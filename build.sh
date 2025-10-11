#!/usr/bin/bash

set -e

tag=$(date +%s)

podman build . --build-arg ALPINE_VER=3.22 -t docker.io/kamaradclimber/kidsproxy:$tag
podman push docker.io/kamaradclimber/kidsproxy:$tag
