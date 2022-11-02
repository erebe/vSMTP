/*
 * vSMTP mail transfer agent
 * Copyright (C) 2022 viridIT SAS
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or any later version.
 *
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see https://www.gnu.org/licenses/.
 *
*/

// use crate::run_test;

// TODO: add more test cases for this example.
//       anti-relaying is embedded in vSMTP core so those tests are disabled.

// run_test! {
//     fn test_check_relay_1,
//     input = [
//         "HELO foo\r\n",
//         "MAIL FROM: <satan@testserver.com>\r\n",
//     ].concat(),
//     expected = [
//         "220 testserver.com Service ready\r\n",
//         "250 Ok\r\n",
//         "554 5.7.1 Relay access denied\r\n",
//     ]
//     .concat(),
//     config = vsmtp_config::Config::from_vsl_file(std::path::PathBuf::from_iter([
//         env!("CARGO_MANIFEST_DIR"),
//         "../../../examples/anti_relaying/vsmtp.vsl"
//     ])).unwrap(),,,,
// }

// run_test! {
//     fn test_check_relay_2,
//     input =  [
//         "HELO foo\r\n",
//         "MAIL FROM: <john.doe@mta-internal.foobar.com>\r\n",
//         "RCPT TO: <satan@example.com>\r\n",
//         "QUIT\r\n"
//     ].concat(),
//     expected = [
//         "220 testserver.com Service ready\r\n",
//         "250 Ok\r\n",
//         "250 Ok\r\n",
//         "554 5.7.1 Relay access denied\r\n",
//         "221 Service closing transmission channel\r\n"
//     ].concat(),
//     config = vsmtp_config::Config::from_vsl_file(std::path::PathBuf::from_iter([
//         env!("CARGO_MANIFEST_DIR"),
//         "../../../examples/anti_relaying/vsmtp.vsl"
//     ])).unwrap(),,,,
// }

// run_test! {
//     fn test_check_relay_3,
//     input = [
//         "HELO foo\r\n",
//         "MAIL FROM: <john.doe@mta-internal.foobar.com>\r\n",
//         "RCPT TO: <green@testserver.com>\r\n",
//         "QUIT\r\n"
//     ].concat(),
//     expected = [
//         "220 testserver.com Service ready\r\n",
//         "250 Ok\r\n",
//         "250 Ok\r\n",
//         "250 Ok\r\n",
//         "221 Service closing transmission channel\r\n",
//     ].concat(),
//     config = vsmtp_config::Config::from_vsl_file(std::path::PathBuf::from_iter([
//         env!("CARGO_MANIFEST_DIR"),
//         "../../../examples/anti_relaying/vsmtp.vsl"
//     ])).unwrap(),,,,
// }
