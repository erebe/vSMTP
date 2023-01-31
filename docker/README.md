# Docker How-to

This directory regroups `Dockerfiles` used to run instances of vSMTP and build / test packages automatically.

## Run vSMTP

The `Dockerfile` available in this repository download, builds and run a single instance of the latest version of vSMTP in a `rust:alpine` image with a minimal configuration setup. to run the instance, simply execute the following command.

```sh
docker run -it viridit/vsmtp:v2.0.0
```

## Build for a specific linux distribution

See the `debian`, `ubuntu` and `redhat` directories.

## X-compilation

> this section is deprecated and will be removed in the future.

From : https://medium.com/@artur.klauser/building-multi-architecture-docker-images-with-buildx-27d80f7e2408

```sh
sudo apt install -y qemu-user-static binfmt-support
sudo apt-get install -y binfmt-support
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes

docker buildx create --name allcpus
docker buildx use allcpus

docker buildx ls
docker buildx inspect --bootstrap
docker buildx build -t viridit/vsmtp:1.3.0 --platform linux/amd64,linux/arm64 --push .
```
