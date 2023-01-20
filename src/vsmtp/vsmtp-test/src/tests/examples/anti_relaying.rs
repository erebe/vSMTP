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

use crate::run_test;

run_test! {
    fn test_check_relay_1,
    input = [
        "HELO foo\r\n",
        // Basic open-relay tentative.
        "MAIL FROM: <john.doe@foobar.com>\r\n",
        "RCPT TO: <satan@any.com>\r\n",
    ],
    expected = [
        "220 testserver.com Service ready\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "554 5.7.1 Relay access denied\r\n",
    ],
    config = vsmtp_config::Config::from_vsl_file(std::path::PathBuf::from_iter([
        env!("CARGO_MANIFEST_DIR"),
        "../../../examples/anti_relaying/vsmtp.vsl"
    ])).unwrap(),
}

run_test! {
    fn test_check_relay_2,
    input = [
        "HELO foo\r\n",
        // Untrusted address.
        "MAIL FROM: <satan@testserver.com>\r\n",
    ],
    expected = [
        "220 testserver.com Service ready\r\n",
        "250 Ok\r\n",
        "451 4.7.1 Sender is not authorized. Please try again.\r\n",
    ],
    config = vsmtp_config::Config::from_vsl_file(std::path::PathBuf::from_iter([
        env!("CARGO_MANIFEST_DIR"),
        "../../../examples/anti_relaying/vsmtp.vsl"
    ])).unwrap(),
}

run_test! {
    fn test_check_relay_3,
    input = [
        "HELO foo\r\n",
        // Authorized email (outgoing).
        "MAIL FROM: <john.doe@example.com>\r\n",
        "RCPT TO: <green@testserver.com>\r\n",
        "QUIT\r\n"
    ],
    expected = [
        "220 testserver.com Service ready\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "221 Service closing transmission channel\r\n",
    ],
    config = vsmtp_config::Config::from_vsl_file(std::path::PathBuf::from_iter([
        env!("CARGO_MANIFEST_DIR"),
        "../../../examples/anti_relaying/vsmtp.vsl"
    ])).unwrap(),
}

run_test! {
    fn test_check_relay_4,
    input = [
        "HELO foo\r\n",
        // Authorized email (internal).
        "MAIL FROM: <john.doe@example.com>\r\n",
        "RCPT TO: <green@example.com>\r\n",
        "QUIT\r\n"
    ],
    expected = [
        "220 testserver.com Service ready\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "221 Service closing transmission channel\r\n",
    ],
    config = vsmtp_config::Config::from_vsl_file(std::path::PathBuf::from_iter([
        env!("CARGO_MANIFEST_DIR"),
        "../../../examples/anti_relaying/vsmtp.vsl"
    ])).unwrap()
}
