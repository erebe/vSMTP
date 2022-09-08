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

use crate::{root_example, test_receiver};

#[tokio::test]
async fn test_greylist() {
    std::fs::File::create(root_example!["greylist/greylist.csv"]).unwrap();

    let toml = include_str!("../../../../../../examples/greylist/vsmtp.toml");
    let config = vsmtp_config::Config::from_toml(toml).unwrap();

    assert!(test_receiver! {
        with_config => config.clone(),
        [
            "HELO foo\r\n",
            "MAIL FROM: <john.doe@example.com>\r\n",
        ].concat(),
        [
            "220 testserver.com Service ready\r\n",
            "250 Ok\r\n",
            "451 4.7.1 Sender is not authorized. Please try again.\r\n",
        ]
        .concat()
    }
    .is_ok());

    // after writing john.die to database, the email is accepted.
    assert!(test_receiver! {
        with_config => config.clone(),
        [
            "HELO foo\r\n",
            "MAIL FROM: <john.doe@example.com>\r\n",
            "QUIT\r\n",
        ].concat(),
        [
            "220 testserver.com Service ready\r\n",
            "250 Ok\r\n",
            "250 Ok\r\n",
            "221 Service closing transmission channel\r\n",
        ]
        .concat()
    }
    .is_ok());

    std::fs::remove_file(root_example!["greylist/greylist.csv"]).unwrap();
}
