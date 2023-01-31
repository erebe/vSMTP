# Docker setup with memcached plugin.

The following docker files installs an instance of vSMTP (using an alpine image) and a memcached database. (via the oficial images)

It is used to test the plugin in our CI environments, but you can launch your own instance via the following command: 

```
$ docker compose build
$ docker compose up
```

vsmtp is accessible via port `10025` on the host.

The docker compose file creates a network between the vsmtp instance and the database, enabling a greylist service to talk with memcache.
