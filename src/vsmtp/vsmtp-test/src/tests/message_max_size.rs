/*
 * vSMTP mail transfer agent
 * Copyright (C) 2022 viridIT SAS
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms &of the GNU General Public License as published by the Free Software
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

use crate::{config, test_receiver};

#[tokio::test]
async fn test_message_size_ko() {
    let mut config = config::local_test();
    config.server.message_size_limit = 1_000_000;

    test_receiver! {
        with_config => config,
        [
            "HELO foobar\r\n",
            "MAIL FROM:<john@doe>\r\n",
            "RCPT TO:<aa@bb>\r\n",
            "DATA\r\n",
            &("X".repeat(1_000_000) + "\r\n"),
            "QUIT\r\n",
        ]
        .concat(),
        [
            "220 testserver.com Service ready\r\n",
            "250 Ok\r\n",
            "250 Ok\r\n",
            "250 Ok\r\n",
            "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
            "552 4.3.1 Message size exceeds fixed maximum message size\r\n",
            "250 Ok\r\n",
            "221 Service closing transmission channel\r\n",
        ]
        .concat()
    }
    .unwrap();
}
