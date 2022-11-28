# Changelog

All notable changes are documented or linked to in this file. The format of the changelog is based on
['Keep a Changelog'](https://keepachangelog.com/en/1.0.0/). In short, this changelog is sorted the most recent
release at the top, and the first section documents features that are in the `development`
branch but have not yet landed in the `main` branch from which releases are generated.

The MSRV (minimum supported Rust version) of the project is documented in the [`Cargo.toml`](Cargo.toml) and in the
[README](README.md). Changes to the MSRV are considered a **non-breaking change** and thus can happen in a *MINOR*
release. They will however *never* happen in a patch release.

<!-- next-header -->

## [Unreleased] - ReleaseDate

### Added

* The `rhai-dylib` crate to handle Rust dynamic libraries with a Rhai API. (#753)

```rust
// import the dynamic library in Rhai.
import "/usr/lib/vsmtp/libvsmtp-plugin-csv" as db;

// use functions defined in the library.
db::csv(#{ ... });
```

* A delegation feature gate on `vsmtp-rule-engine`. (#660)

### Changed

* Configuration is written using Rhai. (#685)

```rust
fn on_config(config) {
  config.version_requirement = ">=1.4.0-rc.0, <2.0.0";

  config.server.name = "my.fqdn.com";

  config.server.system = #{
      user: "root",
      group: "root",
  };

  config.server.interfaces = #{
      addr: ["127.0.0.1:25"],
      addr_submission: ["127.0.0.1:587"],
      addr_submissions: ["127.0.0.1:465"],
  };

  config
}
```

* vSL scripts are split between transaction types and handled sub domains. (#709)

```
/etc/vsmtp
┣ vsmtp.vsl
┣ conf.d/
┃     ┣ config.vsl
┃     ┣ interfaces.vsl
┃     ┣ logs.vsl
┃     ┗ other.vsl
┣ domain-available/
┃     ┣ main.vsl            # Rules executed before the 'mail' stage
┃     ┣ fallback.vsl        # Rules executed if the domain is not handled.
┃     ┣ example.com/
┃     ┃    ┣ incoming.vsl   # Sender domain unknown, recipient domain is 'example.com'.
┃     ┃    ┣ outgoing.vsl   # Sender domain is 'example.com', recipient domain is different.
┃     ┃    ┗ internal.vsl   # Sender & recipient domain are both 'example.com'.
┃     ┗ test.com/
┃         ┗ ...
┗ domain-enabled/
      ┗ example.com -> /etc/vsmtp/domain-available/example.com
```

* The `toml` vsl module has been renamed to `cfg`. (#709)
* Changed the API of objects to be simple rhai functions, removing implicit `export` of
  objects. (#647)

```js
// Old syntax
object localhost ip4 = "127.0.0.1";
// New syntax
const localhost = ip4("127.0.0.1");
```

* Moved the csv database to an external plugin. (#625)
* Moved the mysql database to an external plugin. (#625)
* Moved vSL syntax to a crate for better reusability. (#660)
* Remove Group object & function, replaced by Rhai arrays. (#660)

```js
const localhost = ip4("127.0.0.1");
const john = identifier("john.doe");

// declaration of a group.
const group = [ localhost, john ];
```

* Remove File object, replaced by Rhai arrays. (#660)

```js
// This returns an Array of addresses.
const whitelist = file("/etc/vsmtp/whitelist.txt", "address");

for addr in whitelist {
  // ...
}
```

## [1.3.4] - 2022-10-20

### Fixed

* `forward` && `forward_all` functions now take port into account in socket strings. (#695)

## [1.3.3] - 2022-10-03

### Added

* `--stdout` flag, print logs to stdout. (#579)
* Message size limit configuration. (#580)
* Add the git commit hash to the version string `--version`. (#581)
* Ed25519 support. (#600)

### Changed

* MSRV bumped to 1.63.0 (#638)
* `--no-daemon` flag do not print logs to the standard output anymore. (#579)
* Refactorization of services parsing. (#576)
* `vsmtp` & `vqueue` `--version` flag display build commit. (#585)
* `vqueue` display error if no subcommands are specified. (#585)
* Updated logs to communicate better the state of vSMTP. (#587)
* Remove config field (`server.smtp.required_extension`/`app.logs.format`) and prepare for the all .vsl config.

### Unstable

* Add a `Dockerfile` for the `vsmtp`.

## [1.3.0] - 2022-09-07

### Added

* support for `MySQL` databases. see [`/examples/greylist/mysql`](https://github.com/viridIT/vSMTP/tree/develop/examples/greylist/mysql). (#548)

### Changed

* update the backend of the `SASL` protocol, using a state-of-the-art Rust implementation `rsasl` instead of binding the  `gsasl` C library. (#536)
* update the vsl api with more consistent syntax. (#545)
* Greylist sender domain & return code. (#566, #571)

### Fixed

* IPv6 address for `EHLO` command. (#530)
* Log level ordering. (#565)

### Documented

* improve the vsl api documentation. (#545, #553)

## [1.2.1] - 2022-08-26

### Added

* `check_dmarc` vsl function. (#506)
* Syslog configuration. (#509)
* journald support (#482)

### Fixed

* Missing documentation for vsl api. (#503, #513, #518)
* Don't send greeting code right after receiving STARTTLS. (#504)
* Initialize logs before privilege drop. (#506)
* Documentation errors in Readme and other files.

## [1.2.0] - 2022-08-12

### Added

* "Deliver-To" header to local delivery (mbox & maildir) (#443)
* `lookup` & `rlookup` vsl functions. (#473)
* Support for DKIM. (#457)
* Support for syslogs. (#475)

### Changed

* Stabilization of vsl's api. (#452)
* Replaced `log4rs` by the `tracing` crate for logs. (#460)

## [1.1.3] - 2022-07-12

### Changed

* delegation directives sets the X-VSMTP-DELEGATION
  header in the email to pick up where processing left of. (#438)
* refactored the queue system to make it simpler. (#438)
* multiple delegation directives can be used in a single
  stage with one or multiple services. (#438)
* delegation is available for `postq` & `delivery` only. (#438)

## [1.1.2] - 2022-07-07

### Added

* a `prepend_header` and `append_header` in `vsl` api to push front/back headers in message (#410).
* run the deliveries of message concurrently (by transport method maildir/mbox/...) (#425).

### Changed

* you can now add headers to a message at any stages (instead of preq an later) (#410).

### Fixed

* improve SPF policies (#400).
* produce an error at startup with invalid rules stages (#391).
* fixed a bug where the delivery system would place successfully sent emails into deferred queue when only one MX record was available (#427).

### Breaking Changes

* `vsl` api of SPF has changed (see the documentation <https://vsmtp.rs/start/configuration/hardening.html#using-the-spf-protocol>).
* split `check_relay` to `check_mail_relay` and `check_rcpt_relay` (#412).

## [1.1.0] - 2022-06-20
