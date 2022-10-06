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

run_test! {
    fn vrfy_unimplemented,
    input = concat![
        "HELO foo\r\n",
        "VRFY foobar\r\n",
        "QUIT\r\n",
    ],
    expected = concat![
        "220 testserver.com Service ready\r\n",
        "250 Ok\r\n",
        "502 Command not implemented\r\n",
        "221 Service closing transmission channel\r\n"
    ],,,,,
}
