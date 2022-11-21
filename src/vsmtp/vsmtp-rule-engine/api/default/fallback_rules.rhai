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

//! ### Default Fallback Rules
//!
//! Rules loaded by default when an error occurs in sub domain logic.

#{
    connect:      [ rule "connect deny by default" || deny() ],
    helo:         [ rule "helo deny by default" || deny() ],
    mail:         [ rule "mail deny by default" || deny() ],
    authenticate: [ rule "authenticate deny by default" || deny() ],
    rcpt:         [ rule "rcpt deny by default" || deny() ],
    preq:         [ rule "preq deny by default" || deny() ],
    postq:        [ rule "postq deny by default" || deny() ],
    delivery:     [ rule "delivery deny by default" || deny() ],
}
