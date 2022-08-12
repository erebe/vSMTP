# Config

This folder contain examples of vSMTP configuration.

When the server starts up, the configuration is read,
producing an error if the format is invalid or a field is incorrect.

All fields are optional, and defaults are used if missing.

Check out the [minimal] config to get started and use `vsmtp config-show` to see the default values.

* [simple](./simple.toml)
* [tls](./tls.toml)
* [logging](./logging.toml)
* [secured](./secured.toml)
* [antivirus](./antivirus.toml)

[minimal]: ./minimal.toml
