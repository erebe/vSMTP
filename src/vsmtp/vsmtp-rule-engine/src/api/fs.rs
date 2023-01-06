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

use crate::api::{mail_context::message_id, Context, EngineResult, Message, Server};
use rhai::plugin::{
    mem, Dynamic, EvalAltResult, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};

pub use fs::*;

/// APIs to interact with the file system.
#[rhai::plugin::export_module]
mod fs {
    use crate::get_global;

    /// Export the current raw message to a file as an `eml` file.
    /// The message id of the email is used to name the file.
    ///
    /// # Args
    ///
    /// * `dir` - the directory where to store the email. Relative to the
    /// application path.
    ///
    /// # Effective smtp stage
    ///
    /// `preq` and onwards.
    ///
    /// # Examples
    ///
    /// ```
    /// # let dir = tempfile::tempdir().expect("fs api: failed to create tmpdir");
    /// # let mut config = vsmtp_test::config::local_test();
    /// # config.app.dirpath = dir.path().into();
    ///
    /// # vsmtp_test::vsl::run_with_msg_and_config(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     preq: [
    ///        action "write to file" || fs::write("archives"),
    ///     ]
    /// }
    /// # "#)?.build()),
    /// # None,
    /// # config,
    /// # );
    /// # eprintln!("{:?}", dir.path());
    /// # assert!(std::path::PathBuf::from_iter([
    /// #     dir.path(),
    /// #     &std::path::Path::new("archives")
    /// # ]).exists());
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(name = "write", return_raw)]
    pub fn write_str(ncc: NativeCallContext, dir: &str) -> EngineResult<()> {
        super::write(
            &get_global!(ncc, srv)?,
            &get_global!(ncc, ctx)?,
            &get_global!(ncc, msg)?,
            dir,
        )
    }

    /// Write the content of the current email with it's metadata in a json file.
    /// The message id of the email is used to name the file.
    ///
    /// # Args
    ///
    /// * `dir` - the directory where to store the email. Relative to the
    /// application path.
    ///
    /// # Effective smtp stage
    ///
    /// `preq` and onwards.
    ///
    /// # Examples
    ///
    /// ```
    /// # let dir = tempfile::tempdir().expect("fs api: failed to create tmpdir");
    /// # let mut config = vsmtp_test::config::local_test();
    /// # config.app.dirpath = dir.path().into();
    ///
    /// # vsmtp_test::vsl::run_with_msg_and_config(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     preq: [
    ///        action "write to file" || fs::dump("metadata"),
    ///     ]
    /// }
    /// # "#)?.build()),
    /// # None,
    /// # config,
    /// # );
    /// # eprintln!("{:?}", dir.path());
    /// # assert!(std::path::PathBuf::from_iter([
    /// #     dir.path(),
    /// #     &std::path::Path::new("metadata")
    /// # ]).exists());
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(name = "dump", return_raw)]
    pub fn dump_str(ncc: NativeCallContext, dir: &str) -> EngineResult<()> {
        super::dump(&get_global!(ncc, srv)?, &get_global!(ncc, ctx)?, dir)
    }
}

// TODO: handle canonicalization
fn write(srv: &Server, ctx: &Context, message: &Message, dir: &str) -> EngineResult<()> {
    let mut dir = srv.config.app.dirpath.join(dir);
    std::fs::create_dir_all(&dir).map_err::<Box<EvalAltResult>, _>(|err| {
        format!("cannot create folder '{}': {err}", dir.display()).into()
    })?;

    dir.push(format!("{}.eml", message_id(ctx)?));

    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(&dir)
        .map_err::<Box<EvalAltResult>, _>(|err| {
            format!("failed to write email at {}: {err}", dir.display()).into()
        })?;
    let mut writer = std::io::LineWriter::new(file);

    let body = &message
        .read()
        .map_err::<Box<EvalAltResult>, _>(|e| e.to_string().into())?;

    std::io::Write::write_all(&mut writer, body.inner().to_string().as_bytes())
        .map_err(|err| format!("failed to write email at {dir:?}: {err}").into())
}

fn dump(srv: &Server, ctx: &Context, dir: &str) -> EngineResult<()> {
    let mut dir = srv.config.app.dirpath.join(dir);
    std::fs::create_dir_all(&dir).map_err::<Box<EvalAltResult>, _>(|err| {
        format!("cannot create folder '{}': {err}", dir.display()).into()
    })?;

    dir.push(format!("{}.json", message_id(ctx)?));

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(&dir)
        .map_err::<Box<EvalAltResult>, _>(|err| {
            format!("failed to dump email at {}: {err}", dir.display()).into()
        })?;

    std::io::Write::write_all(
        &mut file,
        serde_json::to_string_pretty(&*vsl_guard_ok!(ctx.read()))
            .map_err::<Box<EvalAltResult>, _>(|err| {
                format!("failed to dump email at {dir:?}: {err}").into()
            })?
            .as_bytes(),
    )
    .map_err(|err| format!("failed to dump email at {dir:?}: {err}").into())
}
