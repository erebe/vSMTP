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

use crate::root_example;
use vsmtp_rule_engine::RuleEngine;

#[test]
fn test_cmd_service() {
    RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(root_example!["services", "cmd.vsl"]),
    )
    .unwrap();
}

#[test]
fn test_smtp_service() {
    RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(root_example!["services", "smtp.vsl"]),
    )
    .unwrap();
}

#[test]
fn test_csv_service() {
    RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(root_example!["services", "csv-database.vsl"]),
    )
    .unwrap();
}

#[test]
#[ignore = "mysql service automatically connects to the desired address, which does not exists when testing. To mock."]
fn test_mysql_service() {
    RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(root_example!["services", "mysql-database.vsl"]),
    )
    .unwrap();
}
