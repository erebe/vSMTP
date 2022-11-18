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
mod examples {
    mod aliases;
    mod anti_relaying;
    mod dnsbl;
    mod family;
    mod message;
}
mod protocol {
    mod clair;
    mod message_max_size;
    mod rset;
    mod vrfy;

    pub mod auth;
    mod tls;
    mod utf8;
}
mod rule_engine {
    mod actions;
    // mod todo;
    mod getters;
    mod rule_default;
    mod rule_triage;
}
mod rules {
    mod codes;
    mod quarantine;
}
mod vqueue;
