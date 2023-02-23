/*
 * vSMTP mail transfer agent
 * Copyright (C) 2022 viridIT SAS
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see https://www.gnu.org/licenses/.
 *
*/

use rhai::{
    plugin::{
        mem, Dynamic, FnAccess, FnNamespace, ImmutableString, NativeCallContext, PluginFunction,
        RhaiResult, TypeId,
    },
    Module,
};

use ldap3::{exop::WhoAmI, LdapConn, LdapError};
use r2d2::ManageConnection;

/// Transforms a generic error into the rhai boxed eval alt result.
macro_rules! rhai_generic_ok {
    ($result:expr) => {
        $result.map_err::<Box<rhai::EvalAltResult>, _>(|e| e.to_string().into())?
    };
}

/// A connection manager for ldap using r2d2.
#[derive(Debug)]
pub struct ConnectionManager {
    url: String,
    tls: Option<LdapTLSParameters>,
    bind: Option<LdapBindParameters>,
}

impl ManageConnection for ConnectionManager {
    type Connection = LdapConn;
    type Error = LdapError;

    /// Connects to a ldap server.
    fn connect(&self) -> Result<LdapConn, LdapError> {
        let mut conn = self.tls.as_ref().map_or_else(
            || LdapConn::new(&self.url),
            |tls| {
                let settings = ldap3::LdapConnSettings::new().set_starttls(tls.starttls);

                let settings = if let Some(cafile) = tls.cafile.as_ref() {
                    let mut root_store = rustls::RootCertStore::empty();
                    let cert = std::fs::File::open(cafile)?;
                    let mut reader = std::io::BufReader::new(cert);

                    root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut reader)?);

                    let config = rustls::ClientConfig::builder()
                        .with_safe_defaults()
                        .with_root_certificates(root_store)
                        .with_no_client_auth();

                    settings.set_config(config.into())
                } else {
                    settings
                };

                LdapConn::with_settings(settings, &self.url)
            },
        )?;

        if let Some(bind) = &self.bind {
            conn.simple_bind(&bind.dn, &bind.pw)?.success()?;
        }

        Ok(conn)
    }

    fn is_valid(&self, conn: &mut LdapConn) -> Result<(), LdapError> {
        conn.extended(WhoAmI).map(|_| ())
    }

    fn has_broken(&self, conn: &mut LdapConn) -> bool {
        conn.extended(WhoAmI).is_err()
    }
}

/// Parameters to bind a connection using a base dn and a password.
#[derive(Debug, serde::Deserialize)]
pub struct LdapBindParameters {
    dn: String,
    pw: String,
}

/// Parameters to connect to the ldap database with defaults.
#[derive(serde::Deserialize)]
pub struct LdapParameters {
    pub url: String,
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub timeout: std::time::Duration,
    #[serde(default = "default_connections")]
    pub connections: rhai::INT,
    #[serde(default)]
    pub tls: Option<LdapTLSParameters>,
    #[serde(default)]
    pub bind: Option<LdapBindParameters>,
}

const fn default_connections() -> rhai::INT {
    4
}

const fn default_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(30)
}

/// Additional TLS parameters for ldap.
#[derive(Debug, serde::Deserialize)]
pub struct LdapTLSParameters {
    #[serde(default)]
    /// Initialize a transaction using the starttls mechanism.
    starttls: bool,
    #[serde(default)]
    /// Read root certificates from a CAFILE.
    cafile: Option<std::path::PathBuf>,
}

#[derive(Clone)]
/// A database connector based on ldap.
pub struct Ldap {
    // /// The url to the database.
    pub url: String,
    // /// connection pool for the database.
    pub pool: r2d2::Pool<ConnectionManager>,
}

impl Ldap {
    /// Create a ldap connection pool with the given parameters.
    pub fn with_parameters(parameters: LdapParameters) -> Result<Self, Box<rhai::EvalAltResult>> {
        Ok(Self {
            url: parameters.url.clone(),
            pool: rhai_generic_ok!(r2d2::Pool::builder()
                .max_size(rhai_generic_ok!(u32::try_from(parameters.connections)))
                .connection_timeout(parameters.timeout)
                .build(ConnectionManager {
                    url: parameters.url,
                    tls: parameters.tls,
                    bind: parameters.bind,
                })),
        })
    }

    /// Get a connection from the pool, convert the error to a rhai error.
    pub fn get(&self) -> Result<r2d2::PooledConnection<ConnectionManager>, String> {
        self.pool
            .get()
            .map_err(|error| format!("failed to get an ldap connection: {error}"))
    }

    /// Use the search query on a connection.
    pub fn search(
        &self,
        base: &str,
        scope: &str,
        filter: &str,
        attrs: Vec<String>,
    ) -> Result<ldap3::SearchResult, ldap3::LdapError> {
        let mut conn = self.get().map_err(|err| ldap3::LdapError::Io {
            source: std::io::Error::new(std::io::ErrorKind::TimedOut, err),
        })?;

        conn.search(
            base,
            Self::ldap_scope_from_string(scope)
                .map_err(|_| ldap3::LdapError::InvalidScopeString(scope.to_owned()))?,
            filter,
            attrs,
        )
    }

    /// Use the compare query on a connection.
    pub fn compare(&self, dn: &str, attr: &str, val: &str) -> Result<bool, String> {
        let mut conn = self.get()?;

        conn.compare(dn, attr, val)
            .map_err::<String, _>(|error| {
                format!("failed to execute ldap compare command: {error}")
            })?
            .equal()
            .map_err::<String, _>(|error| {
                format!("the ldap client returned an non true or false code: {error}")
            })
    }

    /// Converts a string to a ldap scope object.
    fn ldap_scope_from_string(s: &str) -> Result<ldap3::Scope, String> {
        match s {
            "base" => Ok(ldap3::Scope::Base),
            "one" => Ok(ldap3::Scope::OneLevel),
            "sub" => Ok(ldap3::Scope::Subtree),
            scope => Err(format!("'scope' parameter is malformed, it should either be 'base', 'one' or 'sub', not '{scope}'")),
        }
    }

    fn rhai_result_from_ldap(entry: ldap3::ResultEntry) -> rhai::Map {
        let entry = ldap3::SearchEntry::construct(entry);

        rhai::Map::from_iter([
            ("dn".into(), rhai::Dynamic::from(entry.dn)),
            (
                "attrs".into(),
                rhai::Dynamic::from_map(
                    entry
                        .attrs
                        .into_iter()
                        .map(|(key, value)| {
                            (
                                key.into(),
                                value.into_iter().map(rhai::Dynamic::from).collect(),
                            )
                        })
                        .collect::<rhai::Map>(),
                ),
            ),
        ])
    }
}

#[rhai::plugin::export_module]
pub mod ldap {
    pub type Ldap = rhai::Shared<super::Ldap>;

    /// Construct a ldap connection pool pointing to the given ldap server.
    ///
    /// # Args
    ///
    /// * `parameters` - A map with following parameters:
    ///     * `url`             - A string url to connect to the database.
    ///     * `timeout`         - Time allowed between each query to the database. (default: 30s)
    ///     * `connections`     - Number of connections to open to the database. (default: 4)
    ///     * `bind`            - A map of parameters to execute a simple bind operation: (optional, default: no bind)
    ///         * `dn`          - The DN used to bind.
    ///         * `pw`          - The password used to bind.
    ///     * `tls`             - A map with the following parameters: (optional, default: no tls)
    ///         * `starttls`    - `true` to use starttls when connecting to the server. (optional, default: false)
    ///         * `cafile`      - Root certificate path to use when connecting. (optional)
    ///                           If this parameter is not used, the client will load root certificates
    ///                           found in the platform's native certificate store instead.
    ///                           Be careful since loading native certificates, on some platforms,
    ///                           involves loading and parsing a ~300KB disk file.
    ///
    /// # Return
    ///
    /// A service used to query the server pointed by the `url` parameter.
    ///
    /// # Error
    ///
    /// * The service failed to connect to the server.
    /// * The service failed to load root certificates.
    ///
    /// # Note
    ///
    /// It is recommended to create a ldap service in it's own module.
    ///
    /// # Example
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_ldap" as ldap;
    ///
    /// export const directory = ldap::connect(#{
    ///     url: "ldap://ds.example.com:1389 ",
    /// });
    /// ```    
    #[rhai_fn(return_raw)]
    pub fn connect(parameters: rhai::Map) -> Result<Ldap, Box<rhai::EvalAltResult>> {
        let parameters = rhai::serde::from_dynamic::<super::LdapParameters>(&parameters.into())?;

        super::Ldap::with_parameters(parameters).map(rhai::Shared::new)
    }

    // NOTE: `streaming_search()` could be used in case of large results.
    /// Search the ldap server for entries.
    ///
    /// # Args
    ///
    /// * `base`   - The search base, which is the starting point in the DIT for the operation.
    /// * `scope`  - The scope, which bounds the number of entries which the operation will consider
    ///              Can either be `base`, `one` or `sub`.
    /// * `filter` - An expression computed for all candidate entries,
    ///              selecting those for which it evaluates to true.
    /// * `attrs`  - The list of attributes to retrieve from the matching entries.
    ///
    /// # Return
    ///
    /// A list of entries (as maps) containing the queried attributes for each entry.
    ///
    /// * `result`      - Can be "ok" or "error".
    /// * `entries`     - If `result` is set to "ok", contains an array of the following map:
    ///     * `dn`      - The entry DN.
    ///     * `attrs`   - The entry attributes that were searched.
    /// * `error`       - If `result` is set to "error", contains a string with the error.
    ///
    /// # Errors
    ///
    /// * The connection timed out.
    /// * The scope string is invalid.
    ///
    /// # Example
    ///
    /// Build a service in `services/ds.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_ldap" as ldap;
    ///
    /// export const directory = ldap::connect(#{
    ///     url: "ldap://ds.example.com:389 ",
    ///     timeout: "1m",
    ///     connections: 10,
    /// });
    /// ```
    ///
    /// Search the DS during filtering.
    ///
    /// ```text
    /// import "services/ds" as srv;
    ///
    /// #{
    ///     rcpt: [
    ///         rule "check recipient in DS" || {
    ///             let address = rcpt();
    ///             let user = recipient.local_part();
    ///
    ///             const results = srv::directory.search(
    ///                 "ou=People,dc=example,dc=com",
    ///
    ///                 // Search the whole tree.
    ///                 "sub",
    ///
    ///                 // Match on the user id and address.
    ///                 `(|(uid=${user})(mail=${address}))`
    ///
    ///                 // Get all attributes from the entries.
    ///                 ["*"]
    ///             );
    ///
    ///             // ...
    ///         }
    ///     ],
    /// }
    #[rhai_fn(global, return_raw, pure)]
    pub fn search(
        database: &mut Ldap,
        base: &str,
        scope: &str,
        filter: &str,
        attrs: rhai::Array,
    ) -> Result<rhai::Map, Box<rhai::EvalAltResult>> {
        let results = rhai_generic_ok!(database.search(
            base,
            scope,
            filter,
            attrs
                .into_iter()
                .map(|item| item.to_string())
                .collect::<Vec<_>>(),
        ));

        Ok(results.success().map_or_else(
            |error| {
                rhai::Map::from_iter([
                    ("result".into(), "error".into()),
                    ("error".into(), error.to_string().into()),
                ])
            },
            |(entries, _)| {
                rhai::Map::from_iter([
                    ("result".into(), rhai::Dynamic::from("ok")),
                    (
                        "entries".into(),
                        rhai::Dynamic::from_array(
                            entries
                                .into_iter()
                                .map(|entry| {
                                    rhai::Dynamic::from_map(super::Ldap::rhai_result_from_ldap(
                                        entry,
                                    ))
                                })
                                .collect::<rhai::Array>(),
                        ),
                    ),
                ])
            },
        ))
    }

    /// Compare the value(s) of the attribute attr within an entry named by dn with the value val.
    ///
    /// # Args
    ///
    /// * `dn`      - name of the entry.
    /// * `attr`    - The attribute use to compare the value.
    /// * `val`     - expected value of the attribute.
    ///
    /// # Return
    ///
    /// True, if the attribute matches, false otherwise.
    ///
    /// # Example
    ///
    /// Build a service in `services/ds.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_ldap" as ldap;
    ///
    /// export const directory = ldap::connect(#{
    ///     url: "ldap://ds.example.com:389 ",
    ///     timeout: "1m",
    ///     connections: 10,
    /// });
    /// ```
    ///
    /// Compare an entry attribute during filtering.
    ///
    /// ```text
    /// import "services/ds" as srv;
    ///
    /// #{
    ///     rcpt: [
    ///         rule "check recipient in DS" || {
    ///             let address = rcpt();
    ///             let user = recipient.local_part();
    ///
    ///             if srv::directory.compare(
    ///                 // Find the user in our directory.
    ///                 `uid=${user},ou=People,dc=example,dc=org`,
    ///                 // Compare the "address" attribute.
    ///                 "address",
    ///                 // Check if the given recipient address is the same as
    ///                 // the one registered in the directory.
    ///                 address.to_string(),
    ///             ) {
    ///                 log("info", `${user} email address is registered in the directory.`);
    ///             } else {
    ///                 log("warn", `${user}'s email address does not match the one registered in the directory.`);
    ///             }
    ///         }
    ///     ],
    /// }
    #[rhai_fn(global, return_raw, pure)]
    pub fn compare(
        database: &mut Ldap,
        dn: &str,
        attr: &str,
        val: &str,
    ) -> Result<bool, Box<rhai::EvalAltResult>> {
        database
            .compare(dn, attr, val)
            .map_err(std::convert::Into::into)
    }
}
