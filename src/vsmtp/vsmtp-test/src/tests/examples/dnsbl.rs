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

const CONFIG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../examples/dnsbl/vsmtp.vsl"
);

run_test! {
    fn test_dnsbl_1,
    input = [
        "EHLO [222.11.16.196]\r\n",
    ],
    expected = [
        "220 testserver.com Service ready\r\n",
        "451 4.7.1 Sender is not authorized. Please try again.\r\n",
    ],
    config = vsmtp_config::Config::from_vsl_file(CONFIG).unwrap(),
}

run_test! {
    fn test_dnsbl_2,
    input = [
        "HELO foo\r\n",
        "QUIT\r\n",
    ],
    expected = [
        "220 testserver.com Service ready\r\n",
        "250 Ok\r\n",
        "221 Service closing transmission channel\r\n"
    ],
    config = vsmtp_config::Config::from_vsl_file(CONFIG).unwrap(),
}
