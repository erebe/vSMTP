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

use vsmtp_plugins::eval_with_plugin;

/// Constructing the object should work.
macro_rules! test_build_object_ok {
    ($test_name:ident, $object_name:ident, $valid_value:expr) => {
        eval_with_plugin!($test_name, vsmtp_plugin_vsl::plugin::Objects {}, {
            // Try to construct the tested object.
            let object = $object_name($valid_value);

            // check if `to_string` & `to_debug` are implemented.
            print(object);
            debug(object);
        });
    };
}

/// Constructing the object should fail.
macro_rules! test_build_object_err {
    ($test_name:ident, $object_name:ident, $invalid_value:expr) => {
        eval_with_plugin!($test_name, vsmtp_plugin_vsl::plugin::Objects {},
            {
                try {
                    // Check if an invalid construction throws an error.
                    let object = $object_name($invalid_value);

                    throw "the value "
                        + $invalid_value
                        + " should have thrown an error, but instead have been parsed as "
                        + object;

                } catch {
                    // ok!
                }
            }
        );
    };
}

test_build_object_ok!(ip4_ok, ip4, "127.0.0.1");
test_build_object_ok!(ip6_ok, ip6, "::1");
test_build_object_ok!(rg4_ok, rg4, "127.0.0.1/24");
test_build_object_ok!(rg6_ok, rg6, "0:0:0:0:0:0:0:1/32");
test_build_object_ok!(address_ok, address, "john.doe@example.com");
test_build_object_ok!(fqdn_ok, fqdn, "example.com");
test_build_object_ok!(regex_ok, regex, "^[a-z0-9.]+@example.com$");
test_build_object_ok!(identifier_ok, identifier, "john");

test_build_object_err!(ip4_err, ip4, "invalid_value");
test_build_object_err!(ip6_err, ip6, "invalid_format");
test_build_object_err!(rg4_err, rg4, "invalid_format");
test_build_object_err!(rg6_err, rg6, "invalid_format");
test_build_object_err!(address_err, address, "john.doe");
test_build_object_err!(fqdn_err, fqdn, "bad@fqdn");
test_build_object_err!(regex_err, regex, "^¨^^*zef");

// test_build_object_ok!(file, "...", "...");
// test_build_object_ok!(code, "...", "...");
// test_build_object_ok!(code, "...", "...");

eval_with_plugin!(object_file_declaration, vsmtp_plugin_vsl::plugin::Objects {},
    {
        const ip4 = ip4("127.0.0.1");
        const ip6 = ip6("0:0:0:0:0:0:0:1");
        const rg4 = rg4("127.0.0.1/32");
        const rg6 = rg6("0:0:0:0:0:0:0:1/32");
        const address = address("local_part@domain.com");
        const fqdn = fqdn("domain.com");
        const regex = regex("^[a-z0-9.]+@domain.com$");
        const identifier = identifier("local_part");
        const str = "a string";

        const list = [
          ip4,
          ip6,
          address,
          fqdn,
          ip4("0.0.0.0"),
          address("nested@addr.com"),
        ];

        const custom_code = code(220, "this is a custom code.");
        const enhanced_code = code(
          220,
          "2.0.0",
          "this is a long message, a very very long message ... carriage return will be properly added automatically."
        );
    }
);
