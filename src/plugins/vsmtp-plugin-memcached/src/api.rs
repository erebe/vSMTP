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

use rhai::plugin::*;
use rhai::Dynamic;
use std::collections::HashMap;

#[derive(Debug)]
pub struct MemcacheConnectionManager {
    urls: Vec<String>,
}

impl MemcacheConnectionManager {
    pub fn new<C: memcache::Connectable>(target: C) -> MemcacheConnectionManager {
        MemcacheConnectionManager {
            urls: target.get_urls(),
        }
    }
}

impl r2d2::ManageConnection for MemcacheConnectionManager {
    type Connection = memcache::Client;
    type Error = memcache::MemcacheError;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        memcache::Client::connect(self.urls.clone())
    }

    fn is_valid(&self, connection: &mut memcache::Client) -> Result<(), Self::Error> {
        match connection.version() {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn has_broken(&self, _connection: &mut memcache::Client) -> bool {
        false
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct MemcachedParameters {
    pub url: String,
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub timeout: std::time::Duration,
    #[serde(default = "default_connections")]
    pub connections: rhai::INT,
}

const fn default_connections() -> rhai::INT {
    4
}

const fn default_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(30)
}

#[derive(Clone)]
/// A memcached connector.
pub struct CacheConnector {
    /// The url to the memcached server.
    pub url: String,
    /// connection pool for the cache.
    pub pool: r2d2::Pool<MemcacheConnectionManager>,
}

#[derive(Clone, Debug)]
pub struct DbValue {
    pub value: rhai::Dynamic,
    pub expiration: rhai::INT,
    pub cas_id: Option<rhai::INT>,
}

impl memcache::FromMemcacheValueExt for DbValue {
    fn from_memcache_value(
        value: Vec<u8>,
        duration: u32,
        cas: Option<u64>,
    ) -> Result<Self, memcache::MemcacheError> {
        let buffer = String::from_utf8(value)?;

        if let Ok(boolean) = buffer.parse::<bool>() {
            return Ok(DbValue {
                value: Dynamic::from(boolean),
                expiration: duration as rhai::INT,
                cas_id: cas.map(|v| v as rhai::INT),
            });
        }
        if let Ok(integer) = buffer.parse::<i64>() {
            return Ok(DbValue {
                value: Dynamic::from(integer),
                expiration: duration as rhai::INT,
                cas_id: cas.map(|v| v as rhai::INT),
            });
        }
        if let Ok(floating_point) = buffer.parse::<f64>() {
            return Ok(DbValue {
                value: Dynamic::from(floating_point),
                expiration: duration as rhai::INT,
                cas_id: cas.map(|v| v as rhai::INT),
            });
        }
        if let Ok(unsigned_integer) = buffer.parse::<u64>() {
            return Ok(DbValue {
                value: Dynamic::from(unsigned_integer),
                expiration: duration as rhai::INT,
                cas_id: cas.map(|v| v as rhai::INT),
            });
        }
        Ok(DbValue {
            value: Dynamic::from(buffer),
            expiration: duration as rhai::INT,
            cas_id: cas.map(|v| v as rhai::INT),
        })
    }
}

#[derive(Debug)]
struct Wrapper(Dynamic);

impl<W: std::io::Write> memcache::ToMemcacheValue<W> for Wrapper {
    fn get_flags(&self) -> u32 {
        0
    }

    fn get_length(&self) -> usize {
        self.0.to_string().as_bytes().len()
    }

    fn write_to(&self, stream: &mut W) -> std::io::Result<()> {
        stream.write_all(self.0.to_string().as_bytes())
    }
}

impl memcache::FromMemcacheValueExt for Wrapper {
    fn from_memcache_value(
        value: Vec<u8>,
        _: u32,
        _: Option<u64>,
    ) -> Result<Self, memcache::MemcacheError> {
        let buffer = String::from_utf8(value)?;

        if let Ok(boolean) = buffer.parse::<bool>() {
            return Ok(Wrapper(Dynamic::from(boolean)));
        }
        if let Ok(integer) = buffer.parse::<i64>() {
            return Ok(Wrapper(Dynamic::from(integer)));
        }
        if let Ok(floating_point) = buffer.parse::<f64>() {
            return Ok(Wrapper(Dynamic::from(floating_point)));
        }
        if let Ok(unsigned_integer) = buffer.parse::<u64>() {
            return Ok(Wrapper(Dynamic::from(unsigned_integer)));
        }
        Ok(Wrapper(Dynamic::from(buffer)))
    }
}

impl CacheConnector {
    pub fn flush(&self) -> Result<(), Box<rhai::EvalAltResult>> {
        let client = self.pool.get();
        match client {
            Ok(client) => {
                client
                    .flush()
                    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
                Ok(())
            }
            Err(e) => {
                Err(e).map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            }
        }
    }

    pub fn get(&self, key: &str) -> Result<Dynamic, Box<rhai::EvalAltResult>> {
        let client = self.pool.get();
        match client {
            Ok(client) => {
                let result = client
                    .get::<Wrapper>(key)
                    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
                match result {
                    Some(result) => Ok(result.0),
                    None => Ok(Dynamic::UNIT),
                }
            }
            Err(e) => {
                Err(e).map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            }
        }
    }

    pub fn get_with_cas(&self, key: &str) -> Result<DbValue, Box<rhai::EvalAltResult>> {
        let client = self.pool.get();
        match client {
            Ok(client) => {
                let result = client
                    .get::<DbValue>(key)
                    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
                match result {
                    Some(result) => Ok(result),
                    None => Ok(DbValue {
                        value: Dynamic::UNIT,
                        expiration: 0,
                        cas_id: Some(0),
                    }),
                }
            }
            Err(e) => {
                Err(e).map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            }
        }
    }

    pub fn gets(
        &self,
        keys: &[&str],
    ) -> Result<HashMap<String, Dynamic>, Box<rhai::EvalAltResult>> {
        let client = self.pool.get();
        match client {
            Ok(client) => {
                let result = client
                    .gets::<Wrapper>(keys)
                    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
                Ok(result
                    .into_iter()
                    .map(|(key, value)| (key, value.0))
                    .collect())
            }
            Err(e) => {
                Err(e).map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            }
        }
    }

    // TODO: function to expose.
    #[allow(dead_code)]
    pub fn gets_with_cas(
        &self,
        keys: &[&str],
    ) -> Result<HashMap<String, DbValue>, Box<rhai::EvalAltResult>> {
        let client = self.pool.get();
        match client {
            Ok(client) => {
                let result = client
                    .gets::<DbValue>(keys)
                    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
                Ok(result)
            }
            Err(e) => {
                Err(e).map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            }
        }
    }

    pub fn set(
        &self,
        key: &str,
        value: Dynamic,
        duration: u32,
    ) -> Result<(), Box<rhai::EvalAltResult>> {
        let client = self.pool.get();
        match client {
            Ok(client) => {
                client
                    .set(key, Wrapper(value), duration)
                    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
                Ok(())
            }
            Err(e) => {
                Err(e).map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            }
        }
    }

    pub fn cas(
        &self,
        key: &str,
        value: Dynamic,
        expiration: u32,
        cas_id: u64,
    ) -> Result<bool, Box<rhai::EvalAltResult>> {
        let client = self.pool.get();
        match client {
            Ok(client) => {
                let result = client
                    .cas(key, Wrapper(value), expiration, cas_id)
                    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
                Ok(result)
            }
            Err(e) => {
                Err(e).map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            }
        }
    }

    pub fn add(
        &self,
        key: &str,
        value: Dynamic,
        duration: u32,
    ) -> Result<(), Box<rhai::EvalAltResult>> {
        let client = self.pool.get();
        match client {
            Ok(client) => {
                client
                    .add(key, Wrapper(value), duration)
                    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
                Ok(())
            }
            Err(e) => {
                Err(e).map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            }
        }
    }

    pub fn replace(
        &self,
        key: &str,
        value: Dynamic,
        duration: u32,
    ) -> Result<(), Box<rhai::EvalAltResult>> {
        let client = self.pool.get();
        match client {
            Ok(client) => {
                client
                    .replace(key, Wrapper(value), duration)
                    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
                Ok(())
            }
            Err(e) => {
                Err(e).map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            }
        }
    }

    pub fn append(&self, key: &str, value: Dynamic) -> Result<(), Box<rhai::EvalAltResult>> {
        let client = self.pool.get();
        match client {
            Ok(client) => {
                client
                    .append(key, Wrapper(value))
                    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
                Ok(())
            }
            Err(e) => {
                Err(e).map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            }
        }
    }

    pub fn prepend(&self, key: &str, value: Dynamic) -> Result<(), Box<rhai::EvalAltResult>> {
        let client = self.pool.get();
        match client {
            Ok(client) => {
                client
                    .prepend(key, Wrapper(value))
                    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
                Ok(())
            }
            Err(e) => {
                Err(e).map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            }
        }
    }

    pub fn delete(&self, key: &str) -> Result<bool, Box<rhai::EvalAltResult>> {
        let client = self.pool.get();
        match client {
            Ok(client) => {
                let result = client
                    .delete(key)
                    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
                Ok(result)
            }
            Err(e) => {
                Err(e).map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            }
        }
    }

    pub fn increment(&self, key: &str, value: u64) -> Result<(), Box<rhai::EvalAltResult>> {
        let client = self.pool.get();
        match client {
            Ok(client) => {
                client
                    .increment(key, value)
                    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
                Ok(())
            }
            Err(e) => {
                Err(e).map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            }
        }
    }

    pub fn decrement(&self, key: &str, value: u64) -> Result<(), Box<rhai::EvalAltResult>> {
        let client = self.pool.get();
        match client {
            Ok(client) => {
                client
                    .decrement(key, value)
                    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
                Ok(())
            }
            Err(e) => {
                Err(e).map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            }
        }
    }

    pub fn touch(&self, key: &str, duration: u32) -> Result<(), Box<rhai::EvalAltResult>> {
        let client = self.pool.get();
        match client {
            Ok(client) => {
                client
                    .touch(key, duration)
                    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
                Ok(())
            }
            Err(e) => {
                Err(e).map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            }
        }
    }

    pub fn stats(&self) -> Result<String, Box<rhai::EvalAltResult>> {
        let client = self.pool.get();
        match client {
            Ok(client) => {
                let results = client
                    .stats()
                    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
                Ok(results[0]
                    .1
                    .iter()
                    .map(|(key, value)| format!("{key}: {value}"))
                    .collect::<Vec<_>>()
                    .join(", "))
            }
            Err(e) => {
                Err(e).map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            }
        }
    }
}

/// This plugin exposes methods to open a pool of connexions to a memached server using
/// Rhai.
#[rhai::plugin::export_module]
pub mod memcached {
    use std::collections::BTreeMap;

    pub type Cache = rhai::Shared<CacheConnector>;

    /// Open a pool of connections to a Memcached server.
    ///
    /// # Args
    ///
    /// * `parameters` - a map of the following parameters:
    ///     * `url` - a string url to connect to the server.
    ///     * `timeout` - time allowed between each interaction with the server. (default: 30s)
    ///     * `connections` - Number of connections to open to the server. (default: 4)
    ///
    /// # Return
    ///
    /// A service used to access the memcached server pointed by the `url` parameter.
    ///
    /// # Error
    ///
    /// * The service failed to connect to the server.
    ///
    /// # Example
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const cache = cache::connect(#{
    ///     // Connect to a server on the port 11211 with a timeout.
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    #[rhai_fn(global, return_raw)]
    pub fn connect(parameters: rhai::Map) -> Result<Cache, Box<rhai::EvalAltResult>> {
        let parameters = rhai::serde::from_dynamic::<MemcachedParameters>(&parameters.into())?;
        let manager = MemcacheConnectionManager::new(parameters.url.clone());
        Ok(rhai::Shared::new(CacheConnector {
            url: parameters.url,
            pool: r2d2::Pool::builder()
                .max_size(
                    u32::try_from(parameters.connections)
                        .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?,
                )
                .connection_timeout(parameters.timeout)
                .build(manager)
                .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?,
        }))
    }

    /// Flush all cache on the server immediately
    ///
    /// # Example
    ///
    /// Build a service in `services/cache.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const srv = cache::connect(#{
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Flush all cache during filtering.
    ///
    /// ```text
    /// import "services/cache" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "flush the cache" || {
    ///             srv.flush();
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, return_raw, pure)]
    pub fn flush(cache: &mut Cache) -> Result<(), Box<rhai::EvalAltResult>> {
        cache.flush()
    }

    /// Get something from the server.
    ///
    /// # Args
    ///
    /// * `key` - The key you want to get the value from
    ///
    /// # Return
    ///
    /// A rhai::Dynamic with the value inside
    ///
    /// # Example
    ///
    /// Build a service in `services/cache.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const srv = cache::connect(#{
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Get the value wanted during filtering.
    ///
    /// ```text
    /// import "services/cache" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "get value from my memcached server" || {
    ///             // For the sake of this example, we assume that there is a "client_ip" as a key and "0.0.0.0" as its value.
    ///             const client_ip = srv.get("client_ip");
    ///             log("info", `ip of my client is: ${client_ip}`);
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, return_raw, pure)]
    pub fn get(cache: &mut Cache, key: &str) -> Result<Dynamic, Box<rhai::EvalAltResult>> {
        cache.get(key)
    }

    /// Get something from the server.
    ///
    /// # Args
    ///
    /// * `key` - The key you want to get the value from
    ///
    /// # Return
    ///
    /// A rhai::Dynamic with the value inside
    ///
    /// # Example
    ///
    /// Build a service in `services/cache.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const srv = cache::connect(#{
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Get the value wanted during filtering.
    ///
    /// ```text
    /// import "services/cache" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "get value from my memcached server" || {
    ///             // For the sake of this example, we assume that there is a "client_ip" as a key and "0.0.0.0" as its value.
    ///             const client_ip = srv.get("client_ip");
    ///             log("info", `ip of my client is: ${client_ip}`);
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, return_raw, pure)]
    pub fn get_with_cas(cache: &mut Cache, key: &str) -> Result<Dynamic, Box<rhai::EvalAltResult>> {
        let mut map = rhai::Map::new();
        let result = cache.get_with_cas(key)?;
        map.insert("value".into(), result.value);
        map.insert("expiration".into(), rhai::Dynamic::from(result.expiration));
        map.insert("cas_id".into(), rhai::Dynamic::from(result.cas_id));
        Ok(rhai::Dynamic::from_map(map))
    }

    /// Gets multiple value from mutliple key from the server.
    ///
    /// # Args
    ///
    /// * `keys` - The keys you want to get the values from
    ///
    /// # Return
    ///
    /// A rhai::Map<String, rhai::Dynamic> with the values inside
    ///
    /// # Example
    ///
    /// Build a service in `services/cache.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const srv = cache::connect(#{
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Gets all the values wanted during filtering.
    ///
    /// ```text
    /// import "services/cache" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "get value from my memcached server" || {
    ///             // For the sake of this example, we assume that there is a server filled with multiple values
    ///             const client_ips = srv.gets(["client1_ip", "client2_ip", "client3_ip"]);
    ///             log("info", `client 1: ${client_ips["client1_ip"]}`);
    ///             log("info", `client 2: ${client_ips["client2_ip"]}`);
    ///             log("info", `client 3: ${client_ips["client3_ip"]}`);
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, return_raw, pure)]
    pub fn gets(cache: &mut Cache, keys: rhai::Array) -> Result<Dynamic, Box<rhai::EvalAltResult>> {
        let v = keys
            .into_iter()
            .map(|key| key.to_string())
            .collect::<Vec<_>>();
        let v: Vec<&str> = v.iter().map(|x| &**x).collect();
        Ok(rhai::Dynamic::from_map(
            cache
                .gets(&v)?
                .into_iter()
                .map(|(k, v)| (k.into(), v))
                .collect::<BTreeMap<_, _>>(),
        ))
    }

    /// Gets multiple value from mutliple key from the server.
    ///
    /// # Args
    ///
    /// * `keys` - The keys you want to get the values from
    ///
    /// # Return
    ///
    /// A rhai::Map<String, rhai::Dynamic> with the values inside
    ///
    /// # Example
    ///
    /// Build a service in `services/cache.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const srv = cache::connect(#{
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Gets all the values wanted during filtering.
    ///
    /// ```text
    /// import "services/cache" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "get value from my memcached server" || {
    ///             // For the sake of this example, we assume that there is a server filled with multiple values
    ///             const client_ips = srv.gets(["client1_ip", "client2_ip", "client3_ip"]);
    ///             log("info", `client 1: ${client_ips["client1_ip"]}`);
    ///             log("info", `client 2: ${client_ips["client2_ip"]}`);
    ///             log("info", `client 3: ${client_ips["client3_ip"]}`);
    ///         }
    ///     ],
    /// }
    /// ```
    // #[rhai_fn(global, return_raw, pure)]
    // pub fn gets_with_cas(cache: &mut Cache, keys: rhai::Array) -> Result<Dynamic, Box<rhai::EvalAltResult>> {
    //     let v = keys.into_iter().map(|key| key.to_string()).collect::<Vec<_>>();
    //     let v: Vec<&str> = v.iter().map(|x| &**x).collect();
    //     Ok(rhai::Dynamic::from_map(cache.gets_with_cas(&v)?.into_iter().map(|(k, v)| (k.into(), v)).collect::<BTreeMap<_, _>>()))
    // }

    /// Set a value with its associate key into the server with expiration seconds.
    ///
    /// # Args
    ///
    /// * `key` - The key you want to allocate with the value
    /// * `value` - The value you want to store
    /// * `duration` - The duration time you want the value to remain in cache
    ///
    /// # Example
    ///
    /// Build a service in `services/cache.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const srv = cache::connect(#{
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Set a value during filtering.
    ///
    /// ```text
    /// import "services/cache" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "set value into my memcached server" || {
    ///             srv.set("client_ip", "0.0.0.0", 0);
    ///             const client_ip = srv.get("client_ip");
    ///             log("info", `ip of my client is: ${client_ip}`);
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, return_raw, pure)]
    pub fn set(
        cache: &mut Cache,
        key: &str,
        value: Dynamic,
        duration: rhai::INT,
    ) -> Result<(), Box<rhai::EvalAltResult>> {
        cache.set(
            key,
            value,
            u32::try_from(duration)
                .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?,
        )
    }

    /// Compare and swap a key with the associate value into memcached server with expiration seconds.
    ///
    /// # Args
    ///
    /// * `key` - The key you want to swap
    /// * `value` - The value you want to store
    /// * `expiration` - The duration time you want the value to remain in cache
    /// * `cas_id` - The id which is obtained from a previous call to gets
    ///
    /// # Example
    ///
    /// Build a service in `services/cache.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const srv = cache::connect(#{
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Compare and swap a value during filtering
    ///
    /// ```text
    /// import "services/cache" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "cas a key in the server" || {
    ///             srv.set("foo", "bar", 0);
    ///             let result = srv.get_with_cas("foo");
    ///             srv.cas("foo", "bar2", 0, result.cas_id);
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, return_raw, pure)]
    pub fn cas(
        cache: &mut Cache,
        key: &str,
        value: Dynamic,
        expiration: rhai::INT,
        cas_id: rhai::INT,
    ) -> Result<bool, Box<rhai::EvalAltResult>> {
        cache.cas(
            key,
            value,
            u32::try_from(expiration)
                .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?,
            u64::try_from(cas_id)
                .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?,
        )
    }

    /// Add a key with associate value into memcached server with expiration seconds.
    ///
    /// # Args
    ///
    /// * `key` - The key you want to allocate with the value
    /// * `value` - The value you want to store
    /// * `duration` - The duration time you want the value to remain in cache
    ///
    /// # Example
    ///
    /// Build a service in `services/cache.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const srv = cache::connect(#{
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Add a value during filtering.
    ///
    /// ```text
    /// import "services/cache" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "add value into my memcached server" || {
    ///             // Will get an error if the key already exists
    ///             srv.add("client_ip", "0.0.0.0", 0);
    ///             const client_ip = srv.get("client_ip");
    ///             log("info", `ip of my client is: ${client_ip}`);
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, return_raw, pure)]
    pub fn add(
        cache: &mut Cache,
        key: &str,
        value: Dynamic,
        duration: rhai::INT,
    ) -> Result<(), Box<rhai::EvalAltResult>> {
        cache.add(
            key,
            value,
            u32::try_from(duration)
                .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?,
        )
    }

    /// Replace a key with associate value into memcached server with expiration seconds.
    ///
    /// # Args
    ///
    /// * `key` - The key you want to replace with the value
    /// * `value` - The value you want to store
    /// * `duration` - The duration time you want the value to remain in cache
    ///
    /// # Example
    ///
    /// Build a service in `services/cache.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const srv = cache::connect(#{
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Replace a value during filtering.
    ///
    /// ```text
    /// import "services/cache" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "replace value into my memcached server" || {
    ///             srv.set("client_ip", "0.0.0.0", 0);
    ///             // Will get an error if the key doesn't exist
    ///             srv.replace("client_ip", "255.255.255.255", 0);
    ///             const client_ip = srv.get("client_ip");
    ///             log("info", `ip of my client is: ${client_ip}`);
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, return_raw, pure)]
    pub fn replace(
        cache: &mut Cache,
        key: &str,
        value: Dynamic,
        duration: rhai::INT,
    ) -> Result<(), Box<rhai::EvalAltResult>> {
        cache.replace(
            key,
            value,
            u32::try_from(duration)
                .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?,
        )
    }

    /// Append value to the key.
    ///
    /// # Args
    ///
    /// * `key` - The key you want to append with the value
    /// * `value` - The value you want to append
    ///
    /// # Example
    ///
    /// Build a service in `services/cache.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const srv = cache::connect(#{
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Append a value during filtering.
    ///
    /// ```text
    /// import "services/cache" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "append value into my memcached server" || {
    ///             srv.set("client_ip", "0.0.", 0);
    ///             // Will get an error if the key doesn't exist
    ///             srv.append("client_ip", "0.0");
    ///             const client_ip = srv.get("client_ip");
    ///             log("info", `ip of my client is: ${client_ip}`);
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, return_raw, pure)]
    pub fn append(
        cache: &mut Cache,
        key: &str,
        value: Dynamic,
    ) -> Result<(), Box<rhai::EvalAltResult>> {
        cache.append(key, value)
    }

    /// Prepend value to the key.
    ///
    /// # Args
    ///
    /// * `key` - The key you want to prepend with the value
    /// * `value` - The value you want to prepend
    ///
    /// # Example
    ///
    /// Build a service in `services/cache.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const srv = cache::connect(#{
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Prepend a value during filtering.
    ///
    /// ```text
    /// import "services/cache" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "prepend value into my memcached server" || {
    ///             srv.set("client_ip", ".0.0", 0);
    ///             // Will get an error if the key doesn't exist
    ///             srv.prepend("client_ip", "0.0");
    ///             const client_ip = srv.get("client_ip");
    ///             log("info", `ip of my client is: ${client_ip}`);
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, return_raw, pure)]
    pub fn prepend(
        cache: &mut Cache,
        key: &str,
        value: Dynamic,
    ) -> Result<(), Box<rhai::EvalAltResult>> {
        cache.prepend(key, value)
    }

    /// Delete value of the specified key.
    ///
    /// # Args
    ///
    /// * `key` - The key you want the value to be deleted
    ///
    /// # Example
    ///
    /// Build a service in `services/cache.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const srv = cache::connect(#{
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Delete a value during filtering.
    ///
    /// ```text
    /// import "services/cache" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "delete value into my memcached server" || {
    ///             srv.set("client_ip", "0.0.0.0", 0);
    ///             srv.delete("client_ip");
    ///             // Will return nothing
    ///             const client_ip = srv.get("client_ip");
    ///             log("info", `ip of my client is: ${client_ip}`);
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, return_raw, pure)]
    pub fn delete(cache: &mut Cache, key: &str) -> Result<bool, Box<rhai::EvalAltResult>> {
        cache.delete(key)
    }

    /// Increment value of the specified key.
    ///
    /// # Args
    ///
    /// * `key` - The key you want the value to be incremented
    /// * `value` - Amount of the increment
    ///
    /// # Example
    ///
    /// Build a service in `services/cache.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const srv = cache::connect(#{
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Increment a value during filtering.
    ///
    /// ```text
    /// import "services/cache" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "increment value into my memcached server" || {
    ///             srv.set("nb_of_client", 1, 0);
    ///             srv.increment("nb_of_client", 21);
    ///             const nb_of_client = srv.get("nb_of_client");
    ///             log("info", `nb of client is: ${nb_of_client}`);
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, return_raw, pure)]
    pub fn increment(
        cache: &mut Cache,
        key: &str,
        value: rhai::INT,
    ) -> Result<(), Box<rhai::EvalAltResult>> {
        cache.increment(
            key,
            u64::try_from(value)
                .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?,
        )
    }

    /// Decrement value of the specified key.
    ///
    /// # Args
    ///
    /// * `key` - The key you want the value to be decremented
    /// * `value` - Amount of the Decrement
    ///
    /// # Example
    ///
    /// Build a service in `services/cache.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const srv = cache::connect(#{
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Decrement a value during filtering.
    ///
    /// ```text
    /// import "services/cache" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "decrement value into my memcached server" || {
    ///             srv.set("nb_of_client", 21, 0);
    ///             srv.decrement("nb_of_client", 1);
    ///             const nb_of_client = srv.get("nb_of_client");
    ///             log("info", `nb of client is: ${nb_of_client}`);
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, return_raw, pure)]
    pub fn decrement(
        cache: &mut Cache,
        key: &str,
        value: rhai::INT,
    ) -> Result<(), Box<rhai::EvalAltResult>> {
        cache.decrement(
            key,
            u64::try_from(value)
                .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?,
        )
    }

    /// Set a new expiration time for a exist key.
    ///
    /// # Args
    ///
    /// * `key` - The key you want to change the expiration time
    /// * `duration` - Amount of expiration time
    ///
    /// # Example
    ///
    /// Build a service in `services/cache.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const srv = cache::connect(#{
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Change an expiration time during filtering.
    ///
    /// ```text
    /// import "services/cache" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "change expiration time of a value into my memcached server" || {
    ///             srv.set("nb_of_client", 21, 5000);
    ///             srv.touch("nb_of_client", 0);
    ///             const nb_of_client = srv.get("nb_of_client");
    ///             log("info", `nb of client is: ${nb_of_client}`);
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, return_raw, pure)]
    pub fn touch(
        cache: &mut Cache,
        key: &str,
        duration: rhai::INT,
    ) -> Result<(), Box<rhai::EvalAltResult>> {
        cache.touch(
            key,
            u32::try_from(duration)
                .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?,
        )
    }

    /// Only for debugging purposes, get all server's statistics in a formatted string
    ///
    /// # Return
    ///
    /// A formatted string
    ///
    /// # Example
    ///
    /// Build a service in `services/cache.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_memcached" as cache;
    ///
    /// export const srv = cache::connect(#{
    ///     url: "memcache://localhost:11211",
    ///     timeout: "10s",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Display the server statistics during filtering.
    ///
    /// ```text
    /// import "services/cache" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "show statistics of my memcached server" || {
    ///             const stats = srv.stats();
    ///             log("info", stats);
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, return_raw, pure)]
    pub fn stats(cache: &mut Cache) -> Result<String, Box<rhai::EvalAltResult>> {
        cache.stats()
    }
}
