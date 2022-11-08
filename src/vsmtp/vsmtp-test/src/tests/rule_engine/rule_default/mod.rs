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

//! This suit of test aims to check if the rule engine correctly loads
//! default rules if matching vsl scripts are missing.

use crate::run_test;

#[tokio::test]
#[should_panic(expected = "connection at '127.0.0.1:53844' has been denied when connecting.")]
async fn test_missing_main() {
    run_test! {
        input = [ "HELO foo\r\n" ].concat(),
        expected = [
            "220 testserver.com Service ready\r\n",
            // NOTE: should the deny return a specific code when the server is not configured properly ?
            //       i.e. "Server does not accept clients yet"
            "554 permanent problems with the remote server\r\n",
        ].concat(),
        config = vsmtp_config::Config::from_vsl_file(std::path::PathBuf::from_iter([
            env!("CARGO_MANIFEST_DIR"),
            "src/tests/rule_engine/rule_default/config_missing_main/vsmtp.vsl"
        ])).unwrap(),,,,
    }
    .unwrap();
}

run_test! {
    fn test_missing_fallback,
    input = [
        "HELO foo\r\n",
        "mail from: <any@any.com>\r\n",
        "rcpt to: <unknown@any.com>\r\n",
        "rcpt to: <someone@any.com>\r\n",
        "QUIT\r\n",
    ].concat(),
    expected = [
        "220 testserver.com Service ready\r\n",
        "250 Ok\r\n",
        "0 We accept everybody, even 'any.com'\r\n",
        // NOTE: should the deny return a specific code when the fallback is missing for the rcpt stage ?
        //       i.e. ""
        "550-5.1.1 The email account that you tried to reach does not exist. Please try\r\n",
        "550 5.1.1  again.\r\n",
        "550-5.1.1 The email account that you tried to reach does not exist. Please try\r\n",
        "550 5.1.1  again.\r\n",
        "221 Service closing transmission channel\r\n",
    ].concat(),
    config = vsmtp_config::Config::from_vsl_file(std::path::PathBuf::from_iter([
        env!("CARGO_MANIFEST_DIR"),
        "src/tests/rule_engine/rule_default/config_missing_fallback/vsmtp.vsl"
    ])).unwrap(),,,,
}

run_test! {
    fn test_missing_domain_scripts,
    input = [
        "HELO foo\r\n",
        // Default outgoing.
        "mail from: <any@example.com>\r\n",
        "rcpt to: <john.doe@example.com>\r\n",
        "rcpt to: <john.doe@other.com>\r\n",
        "RSET\r\n",
        // Default incoming.
        "mail from: <any@other.com>\r\n",
        "rcpt to: <any@example.com>\r\n",
        "rcpt to: <any@other.com>\r\n",

        "QUIT\r\n",
    ].concat(),
    expected = [
        "220 testserver.com Service ready\r\n",
        "250 Ok\r\n",
        // Should have auth here by default.
        "250 Ok\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        // Rset.
        "250 Ok\r\n",
        // Main "mail" stage is run here.
        "0 We accept everybody, even 'other.com'\r\n",
        // handled recipient in incoming are discarded by default.
        "550-5.1.1 The email account that you tried to reach does not exist. Please try\r\n",
        "550 5.1.1  again.\r\n",
        // Fallback called.
        "550 unhandled domain. sender='other.com', rcpt='other.com'\r\n",
    ].concat(),
    config = vsmtp_config::Config::from_vsl_file(std::path::PathBuf::from_iter([
        env!("CARGO_MANIFEST_DIR"),
        "src/tests/rule_engine/rule_default/config_missing_domain_scripts/vsmtp.vsl"
    ])).unwrap(),,,,
}
