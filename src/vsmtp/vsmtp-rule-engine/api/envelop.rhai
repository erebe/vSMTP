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

/// Rewrite the sender received from the `MAIL FROM` command.
///
/// # Args
///
/// * `new_addr` - the new sender address to set.
///
/// # Effective smtp stage
///
/// `mail` and onwards.
///
/// # Example
/// ```js
/// #{
///     preq: [
///        action "rewrite envelop" || rewrite_mail_from_envelop("unknown@example.com"),
///     ]
/// }
/// ```
///
/// # Module:Envelop
fn rewrite_mail_from_envelop(new_addr) { sys::rewrite_mail_from_envelop(ctx(), new_addr) }

/// Replace a recipient received by a `RCPT TO` command.
///
/// # Args
///
/// * `old_addr` - the recipient to replace.
/// * `new_addr` - the new address to use when replacing `old_addr`.
///
/// # Effective smtp stage
///
/// `rcpt` and onwards.
///
/// # Example
/// ```js
/// #{
///     preq: [
///        action "rewrite envelop" || rewrite_rcpt_envelop("john.doe@example.com", "john.main@example.com"),
///     ]
/// }
/// ```
///
/// # Module:Envelop
fn rewrite_rcpt_envelop(old_addr, new_addr) { sys::rewrite_rcpt_envelop(ctx(), old_addr, new_addr) }

/// Add a new recipient to the envelop. Note that this does not add
/// the recipient to the `To` header. Use `add_rcpt_message` for that.
///
/// # Args
///
/// * `rcpt` - the new recipient to add.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// #{
///     connect: [
///        // always deliver a copy of the message to "john.doe@example.com".
///        action "rewrite envelop" || add_rcpt_envelop("john.doe@example.com"),
///     ]
/// }
/// ```
///
/// # Module:Envelop
fn add_rcpt_envelop(rcpt) { sys::add_rcpt_envelop(ctx(), rcpt) }

/// Remove a recipient from the envelop. Note that this does not remove
/// the recipient from the `To` header. Use `remove_rcpt_message` for that.
///
/// # Args
///
/// * `rcpt` - the recipient to remove.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// #{
///     preq: [
///        // never deliver to "john.doe@example.com".
///        action "rewrite envelop" || remove_rcpt_envelop("john.doe@example.com"),
///     ]
/// }
/// ```
///
/// # Module:Envelop
fn remove_rcpt_envelop(rcpt) { sys::remove_rcpt_envelop(ctx(), rcpt) }

/// Add a recipient as a blind carbon copy. The equivalent of `add_rcpt_envelop`.
///
/// # Args
///
/// * `rcpt` - the recipient to add as a blind carbon copy.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// #{
///     connect: [
///        // set "john.doe@example.com" as a blind carbon copy.
///        action "bcc" || bcc("john.doe@example.com"),
///     ]
/// }
/// ```
///
/// # Module:Envelop
fn bcc(rcpt) { add_rcpt_envelop(rcpt) }

/// Rewrite the value of the `MAIL FROM` command has well has
/// the `From` header.
///
/// # Args
///
/// * `new_addr` - the new sender address to set.
///
/// # Effective smtp stage
///
/// `preq` and onwards.
///
/// # Example
/// ```js
/// #{
///     preq: [
///        action "rewrite sender" || rewrite_mail_from("john.doe@example.com"),
///     ]
/// }
/// ```
///
/// # Module:Envelop
fn rewrite_mail_from(new_addr) {
    sys::rewrite_mail_from_envelop(ctx(), new_addr);
    sys::rewrite_mail_from_message(msg(), new_addr)
}
