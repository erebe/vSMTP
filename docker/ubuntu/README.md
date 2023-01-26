# Dockerfiles for ubuntu

The following `Dockerfiles` are used in GitHub Actions to build and test automatically `.deb` packages for [ubuntu](https://www.ecosia.org/search?tt=e8eb07a6&q=ubuntu&addon=brave).

## Build test and extract a package

Please see the [debian docker package README](../debian/README.md) as the workflow is almost the same.

The only difference is that you can add ubuntu's version as a build argument:

```sh
# This command is run from the root of the vSMTP repository.
$ docker image build \
  --build-arg UBUNTU_VERSION=20.04 \ # We will build vSMTP for ubuntu 20.04
  -t vsmtp-ubuntu-20.04-amd64 \
  -f docker/ubuntu/Dockerfile.amd64 \
  docker/ubuntu
```

In vSMTP's GitHub Actions, `ubuntu:20.04` and `ubuntu:22.04` packages are built and distributed. Feel free to try out other ubuntu versions, although they might not work.
