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

/// Set the delivery method to forwarding for a single recipient.
/// After all rules are evaluated, forwarding will be used to deliver
/// the email to the recipient.
///
/// # Args
///
/// * `rcpt` - the recipient to apply the method to.
/// * `target` - the target to forward the email to.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// #{
///     delivery: [
///        action "setup forwarding" || forward("john.doe@example.com", "mta-john.example.com"),
///     ]
/// }
/// ```
///
/// # Module:Delivery
fn forward(rcpt, target) { sys::forward(ctx(), rcpt, target) }

/// Set the delivery method to forwarding for all recipients.
/// After all rules are evaluated, forwarding will be used to deliver
/// the email.
///
/// # Args
///
/// * `target` - the target to forward the email to.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// #{
///     delivery: [
///        action "setup forwarding" || forward_all("mta-john.example.com"),
///     ]
/// }
/// ```
///
/// # Module:Delivery
fn forward_all(target) { sys::forward_all(ctx(), target) }

/// Set the delivery method to deliver for a single recipient.
/// After all rules are evaluated, the email will be sent
/// to the recipient using the domain of its address.
///
/// # Args
///
/// * `rcpt` - the recipient to apply the method to.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// #{
///     delivery: [
///        action "setup delivery" || deliver("john.doe@example.com"),
///     ]
/// }
/// ```
///
/// # Module:Delivery
fn deliver(rcpt) { sys::deliver(ctx(), rcpt) }

/// Set the delivery method to deliver for all recipients.
/// After all rules are evaluated, the email will be sent
/// to all recipients using the domain of their respective address.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// #{
///     delivery: [
///        action "setup delivery" || deliver_all(),
///     ]
/// }
/// ```
///
/// # Module:Delivery
fn deliver_all() { sys::deliver_all(ctx()) }

/// Set the delivery method to mbox for a recipient.
/// After all rules are evaluated, the email will be stored
/// localy in the mail box of the recipient if it exists on the server.
///
/// # Args
///
/// * `rcpt` - the recipient to apply the method to.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// #{
///     delivery: [
///        action "setup mbox" || mbox("john.doe@example.com"),
///     ]
/// }
/// ```
///
/// # Module:Delivery
fn mbox(rcpt) { sys::mbox(ctx(), rcpt) }

/// Set the delivery method to mbox for all recipients.
/// After all rules are evaluated, the email will be stored
/// localy in the mail box of all recipients if they exists on the server.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// #{
///     delivery: [
///        action "setup mbox" || mbox_all(),
///     ]
/// }
/// ```
///
/// # Module:Delivery
fn mbox_all() { sys::mbox_all(ctx()) }

/// Set the delivery method to maildir for a recipient.
/// After all rules are evaluated, the email will be stored
/// localy in the `~/Maildir/new/` folder of the recipient's user if it exists on the server.
///
/// # Args
///
/// * `rcpt` - the recipient to apply the method to.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// #{
///     delivery: [
///        action "setup maildir" || maildir("john.doe@example.com"),
///     ]
/// }
/// ```
///
/// # Module:Delivery
fn maildir(rcpt) { sys::maildir(ctx(), rcpt) }

/// Set the delivery method to maildir for all recipients.
/// After all rules are evaluated, the email will be stored
/// localy in each `~/Maildir/new` folder of they respective recipient
/// if they exists on the server.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// #{
///     delivery: [
///        action "setup mbox" || mbox_all(),
///     ]
/// }
/// ```
///
/// # Module:Delivery
fn maildir_all() { sys::maildir_all(ctx()) }

/// Disable the delivery for a single recipient.
///
/// # Args
///
/// * `rcpt` - the recipient to apply the method to.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// #{
///     delivery: [
///        action "disable delivery" || disable_delivery("john.doe@example.com"),
///     ]
/// }
/// ```
///
/// # Module:Delivery
fn disable_delivery(rcpt) { sys::disable_delivery(ctx(), rcpt) }

/// Disable delivery for all single recipients.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// #{
///     delivery: [
///        action "disable delivery" || disable_delivery_all(),
///     ]
/// }
/// ```
///
/// # Module:Delivery
fn disable_delivery_all() { sys::disable_delivery_all(ctx()) }
