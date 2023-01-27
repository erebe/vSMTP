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

use std::process::Command;

fn main() {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map(|out| out.stdout)
        .unwrap_or_else(|_| "unknown".as_bytes().to_vec());

    println!(
        "cargo:rustc-env=GIT_HASH={}",
        String::from_utf8(output).expect("failed to convert hash to valid utf8")
    );

    if let Ok(docs_path) = std::env::var("DOCS_DIR") {
        let mut engine = vsmtp_rule_engine::RuleEngine::new_rhai_engine();

        vsmtp_rule_engine::RuleEngine::build_static_modules(
            &mut engine,
            &vsmtp_config::Config::default(),
        )
        .expect("failed to build static modules");

        let docs = rhai_autodocs::generate_documentation(&engine, false)
            .expect("failed to generate documentation");

        write_docs(&docs_path, &docs);
    }
}

fn write_docs(path: &str, docs: &rhai_autodocs::ModuleDocumentation) {
    std::fs::write(
        std::path::PathBuf::from_iter([path, &format!("fn::{}.md", &docs.name)]),
        &docs.documentation,
    )
    .expect("failed to write documentation");

    for doc in &docs.sub_modules {
        write_docs(path, doc);
    }
}
