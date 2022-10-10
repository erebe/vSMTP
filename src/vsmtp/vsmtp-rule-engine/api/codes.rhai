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

//! ### Codes
//!
//! This module contains predefined codes for SMTP responses.

// Relay
export const code554_7_1 = code(554, "5.7.1", "Relay access denied");

// Email authentication status codes
//
// See. RFC 7372 for updated codes RFC

// DKIM Failure codes (RFC 6376)
export const code550_7_20 = code(550, "5.7.20", "No passing DKIM signature found");
export const code550_7_21 = code(550, "5.7.21", "No acceptable DKIM signature found");
export const code550_7_22 = code(550, "5.7.22", "No valid author-matched DKIM signature found");

// SPF Failure codes (RFC 7208)
export const code550_7_23 = code(550, "5.7.23", "SPF validation failed");
export const code451_7_24 = code(451, "5.7.24", "SPF validation error");
export const code550_7_24 = code(550, "5.7.24", "SPF validation error");

// Reverse DNS Failure code
export const code550_7_25 = code(550, "5.7.25", "Reverse DNS validation failed");

// Multiple Authentication Failures code
export const code550_7_26 = code(500, "5.7.26", "Multiple authentication checks failed");

// Null MX codes (RFC 7505)
export const code550_7_27 = code(550, "5.7.27", "Sender address has null MX");
export const code556_1_10 = code(556, "5.1.10", "Recipient address has null MX");

// Greylisting code (https://www.rfc-editor.org/rfc/rfc6647.html#section-2.1)
export const code_greylist = code(451, "4.7.1", "Sender is not authorized. Please try again.");
