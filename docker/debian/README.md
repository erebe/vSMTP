# Dockerfiles for debian

The following `Dockerfiles` are used in GitHub Actions to build and test automatically `.deb` packages for [debian bullseye](https://www.ecosia.org/search?tt=e8eb07a6&q=debian%20bullseye&addon=brave).

## Build a package

> 🚧 arm64 build architecture is still a work in progress, see https://github.com/viridIT/vSMTP/issues/964

A new debian package can be built using the following commands:

```sh
# This command is run from the root of the vSMTP repository.
$ docker image build \
    -t vsmtp-debian-amd64 \
    -f docker/debian/Dockerfile.amd64 \
    docker/debian
```

The previous command builds vSMTP from the `main` branch. If you want to clone vSMTP from a different branch, use the following build argument.

```sh
$ docker image build \
    --build-arg VSMTP_BRANCH=my-branch \
    -t vsmtp-debian-amd64 \
    -f docker/debian/Dockerfile.amd64 \
    docker/debian
```

The previous commands first clone and build a debian package containing vSMTP and all public plugins. [`lintian`](https://lintian.debian.org/) will then check that the package is compliant with the Debian package policy. 

## Test a package

The built package can be tested using [`piuparts`](https://wiki.debian.org/piuparts), a `.deb` package installation, upgrading, and removal testing tool.

To run `piuparts` on the previously built image, simply run the following command.

```sh
docker run --privileged --name piuparts-debian \
  vsmtp-debian-amd64
```

> `piuparts` require the `--privileged` flag because it will attempt to mount `/proc` and other files that needs elevated privileges.
> If you find a way to execute `piuparts` without this flag, feel free to open a PR or an issue.

## Extract a package

Now that the package as been built and tested, it is possible to extract it to your machine using the following command.

```sh
$ docker cp piuparts-debian:./vsmtp.deb \
    vsmtp-debian_amd64.deb
```

Then you can install and test vSMTP on your machine by installing the package with `apt`.

```sh
apt install ./vsmtp-debian_amd64.deb
```
