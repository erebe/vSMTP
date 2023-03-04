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

use crate::run_test;

#[test_log::test(tokio::test(flavor = "multi_thread", worker_threads = 2))]
async fn dotenv() {
    let path = std::env::current_dir()
        .unwrap()
        .join("src/tests/rules/test.env");
    dotenv::from_path(path).unwrap();

    run_test! {
        input = [
            "HELO foobar\r\n",
        ],
        expected = [
            "220 testserver.com Service ready\r\n",
            "250 smtp.server1.tld welcome foobar\r\n"
        ],
        hierarchy_builder = move |builder| Ok(
            builder
                .add_root_filter_rules(r#"
                #{
                    helo: [
                        rule "send my greetings" || {
                            state::accept(`250 ${env("MY_SERVER")} welcome ${ctx::helo()}`)
                        }
                    ]
                }
                "#)?
                .build()
            ),
    };
}
