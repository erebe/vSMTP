//! vSMTP documentation generator.
//!
//! A binary that generates markdown documentation from vsl's API.

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

#![doc(html_no_source)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
//
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::cargo)]
//
#![allow(clippy::use_self)] // false positive with enums

use std::io::Write;

use rhai::packages::Package;
use vsmtp_rule_engine::{api::SharedObject, api::StandardVSLPackage, RuleEngine};

const MODULE_SYNTAX: &str = "# Module:";

#[derive(Clone, Eq)]
struct Module {
    name: String,
    description: String,
}

impl std::hash::Hash for Module {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        self.name.hash(state);
    }
}

impl PartialEq for Module {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Module {
    fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
        }
    }
}

/// Generate a markdown table for each variables found in a module.
fn generate_variable_documentation_from_module(module: &rhai::Module) -> String {
    let (var_count, _, _) = module.count();

    let mut variables_doc = Vec::with_capacity(var_count);

    for (name, value) in module.iter_var() {
        variables_doc.push(format!(
            "|`{}`|{}|",
            name,
            if value.is::<SharedObject>() {
                format!("{:?}", *value.clone_cast::<SharedObject>())
            } else {
                format!("{:?}", value)
            }
        ));
    }

    format!("|name|value|\n| - | - |\n{}\n", variables_doc.join("\n"))
}

/// Generate markdown documentation for each functions in a module.
/// Functions can have a "# Markdown:{module}" syntax in their comments
/// to filter them by module.
///
/// If a module is not specified in `module_names`, the program will panic.
/// If a module is not specified in a function comment, it will be put in
/// the "other" module.
fn generate_function_documentation_from_module(
    modules_metadata: &[Module],
    module: &rhai::Module,
) -> Vec<(String, String, String)> {
    let mut functions_doc: std::collections::HashMap<Module, Vec<_>> = modules_metadata
        .iter()
        .map(|module| (module.clone(), vec![]))
        .collect();

    for (_, _, _, _, metadata) in module.iter_script_fn_info() {
        let comments = &metadata
            .comments
            .iter()
            .map(|comment| format!("{}\n", &comment[3..]))
            .collect::<String>();

        let module = metadata
            .comments
            .iter()
            .find_map(|line| {
                line.find(MODULE_SYNTAX)
                    .map(|index| &line[index + MODULE_SYNTAX.len()..])
            })
            .unwrap_or("other");

        let comments = comments.replace(&format!("{MODULE_SYNTAX}{module}"), "");

        functions_doc
            .entry(Module::new(module, ""))
            .or_default()
            .push(format!(
                r"<details>
<summary>
<code>
{}({})
</code>
</summary>
<br/>
<div style='padding: 10px; border-radius: 5px; border-style: solid; border-color: white'>
{}
</div>
<br/>
</details>",
                metadata.name,
                metadata.params.join(", "),
                &comments
            ));
    }

    let sorted = modules_metadata.iter().fold(vec![], |mut acc, module| {
        acc.push((
            module.name.to_string(),
            module.description.to_string(),
            functions_doc
                .get(module)
                .unwrap_or_else(|| panic!("the {} module isn't known", module.name))
                .clone(),
        ));

        acc
    });

    sorted
        .into_iter()
        .map(|(name, description, mut functions)| {
            functions.sort();
            (name, description, functions.join("\n"))
        })
        .collect::<Vec<_>>()
}

// TODO: find a way to incorporate native functions metadata and documentation.
//         - use docs.rs to get into native functions ? => not user friendly
//         - wrap 'sys' api into rhai functions ?       => might be cumbersome.

fn main() {
    let mut engine = RuleEngine::new_compiler(&vsmtp_config::Config::default());
    let vsl_native_module = StandardVSLPackage::new().as_shared_module();

    engine.register_static_module("sys", vsl_native_module);
    let vsl_rhai_module = RuleEngine::compile_api(&engine).expect("failed to compile vsl's api");

    let functions = generate_function_documentation_from_module(
        &[
            Module::new("Status", "The state of an SMTP transaction can be changed through specific functions from this module."),
            Module::new("Transaction", "At each SMTP stage, data from the client is received via 'SMTP commands'. This module lets you query the content of the commands."),
            Module::new("Connection", "Metadata is available for each client, this module lets you query those metadatas."),
            Module::new("Auth", "This module contains authentication mechanisms to secure your server."),
            Module::new("Envelop", "The SMTP envelop can be mutated by several function from this module."),
            Module::new("Message", "Those methods are used to query data from the email and/or mutate it."),
            Module::new("Delivery", "Those methods are used to setup the method of delivery for one / every recipient."),
            Module::new("Security", "This module contains multiple security functions that you can use to protect your server."),
            Module::new("Services", "Services are external programs that can be used via the functions available in this module."),
            Module::new("Utils", "Those miscellaneous functions lets you query data from your system, log stuff, perform dns lookups etc ..."),
        ],
        &vsl_rhai_module,
    );

    let variables = generate_variable_documentation_from_module(&vsl_rhai_module);

    let mut args = std::env::args();

    args.next();

    let mut path: std::path::PathBuf = args
        .next()
        .expect("The first argument must be the folder where the documentation will be dumped.")
        .parse()
        .expect("The documentation generation path is not valid");

    path.push("any.md");

    for (module, description, functions) in functions {
        path.set_file_name(format!("{}.md", module));
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .unwrap();

        file.write_all(format!("# {}\n## {}\n", module, description).as_bytes())
            .expect("failed to write function docs");
        file.write_all(functions.as_bytes())
            .expect("failed to write function docs");
    }

    path.set_file_name("Variables.md");

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .unwrap();

    file.write_all(b"# Variables\n")
        .expect("failed to write variable docs");
    file.write_all(variables.as_bytes())
        .expect("failed to write variable docs");
}
