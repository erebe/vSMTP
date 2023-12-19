#!/bin/bash


docker image build  \
    --build-arg UBUNTU_VERSION=22.04 \
    -t vsmtp-ubuntu-22.04-amd64 \
    -f docker/ubuntu/Dockerfile.amd64 .

docker run --privileged --name vsmtp vsmtp-ubuntu-22.04-amd64
docker cp vsmtp:./vsmtp.deb .

