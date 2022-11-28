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

// use vsmtp_plugins::eval_with_plugin;

// eval_with_plugin!(get_local_part, vsmtp_plugin_vsl::plugin::Objects {}, {
//     const expected = "john.doe";
//     const user = address("john.doe@example.com").local_part;

//     if user != expected {
//         throw "local part isn't equals to " + expected + ", got: " + user;
//     }
// });

// eval_with_plugin!(get_local_parts, vsmtp_plugin_vsl::plugin::Objects {}, {
//     const expected = ["john.doe", "green.foo"];
//     const users = [
//         address("john.doe@example.com"),
//         "green.foo@example.com"
//     ].local_parts;

//     if users != expected {
//         throw "local parts are not equals to " + expected + ", got: " + users;
//     }
// });

// eval_with_plugin!(get_domain, vsmtp_plugin_vsl::plugin::Objects {}, {
//     const expected = "example.com";
//     const fqdn = address("john.doe@example.com").domain;

//     if fqdn != expected {
//         throw "domain isn't equals to " + expected + ", got: " + fqdn;
//     }
// });
