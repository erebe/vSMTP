# Docker How-to

## X-compilation

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
