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

use crate::{get_root_domain, ParseError};

#[derive(Debug, Clone, PartialEq, Eq, strum::EnumString, strum::Display)]
#[strum(serialize_all = "UPPERCASE")]
pub enum Version {
    Dmarc1,
}

#[derive(Debug, Clone, strum::EnumString, strum::Display)]
enum AlignmentMode {
    #[strum(serialize = "r")]
    Relaxed,
    #[strum(serialize = "s")]
    Strict,
}

#[derive(Debug, Clone, strum::EnumString, strum::Display)]
enum FailureReportOption {
    #[strum(serialize = "0")]
    All,
    #[strum(serialize = "1")]
    Any,
    #[strum(serialize = "d")]
    Dkim,
    #[strum(serialize = "s")]
    Spf,
}

#[derive(Debug, Clone, strum::EnumString, strum::Display)]
#[strum(serialize_all = "lowercase")]
enum ReceiverPolicy {
    None,
    Quarantine,
    Reject,
}

#[derive(Debug, Clone, strum::EnumString, strum::Display)]
enum ReportFailure {
    #[strum(serialize = "afrf")]
    AuthReportFailureFormat,
}

/// DNS record `_dmarc.{domain}`
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Record {
    version: Version,
    adkim: AlignmentMode,
    aspf: AlignmentMode,
    failure_report_options: Vec<FailureReportOption>,
    receiver_policy: ReceiverPolicy,
    receiver_policy_subdomain: Option<ReceiverPolicy>,
    percentage: u8, // 0-100
    report_failure: ReportFailure,
    report_interval: u32,
    // TODO: parse dmarc uri
    report_aggregate_feedback: Vec<String>,
    // TODO: parse dmarc uri
    report_specific_message: Vec<String>,
}

impl Record {
    ///
    #[must_use]
    pub fn get_policy(&self) -> String {
        // TODO: handle subdomain ?
        self.receiver_policy.to_string()
    }

    ///
    #[must_use]
    pub fn dkim_is_aligned(&self, rfc5322_from: &str, dkim_domain: &str) -> bool {
        match self.adkim {
            AlignmentMode::Relaxed => {
                let (root_rfc5322_from, root_domain_used) = (
                    match get_root_domain(rfc5322_from) {
                        Ok(root_rfc5322_from) => root_rfc5322_from,
                        Err(e) => {
                            tracing::warn!("{e}");
                            return false;
                        }
                    },
                    match get_root_domain(dkim_domain) {
                        Ok(root_domain_used) => root_domain_used,
                        Err(e) => {
                            tracing::warn!("{e}");
                            return false;
                        }
                    },
                );

                root_rfc5322_from == root_domain_used
            }
            AlignmentMode::Strict => rfc5322_from == dkim_domain,
        }
    }

    ///
    #[must_use]
    pub fn spf_is_aligned(&self, rfc5322_from: &str, spf_domain: &str) -> bool {
        match self.aspf {
            AlignmentMode::Relaxed => {
                let (root_rfc5322_from, root_spf_domain) = (
                    match get_root_domain(rfc5322_from) {
                        Ok(root_rfc5322_from) => root_rfc5322_from,
                        Err(e) => {
                            tracing::warn!("{e}");
                            return false;
                        }
                    },
                    match get_root_domain(spf_domain) {
                        Ok(root_spf_domain) => root_spf_domain,
                        Err(e) => {
                            tracing::warn!("{e}");
                            return false;
                        }
                    },
                );

                root_rfc5322_from == root_spf_domain
            }
            AlignmentMode::Strict => rfc5322_from == spf_domain,
        }
    }
}

impl std::str::FromStr for Record {
    type Err = ParseError;

    #[allow(clippy::too_many_lines)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut adkim = AlignmentMode::Relaxed;
        let mut aspf = AlignmentMode::Relaxed;
        let mut failure_report_options = vec![FailureReportOption::All];
        let mut receiver_policy = None;
        let mut receiver_policy_subdomain = None;
        let mut percentage = 100u8;
        let mut version = None;
        let mut report_failure = ReportFailure::AuthReportFailureFormat;
        let mut report_interval = 86400;
        let mut report_aggregate_feedback = vec![];
        let mut report_specific_message = vec![];

        for i in s
            .split(';')
            .map(|tag| tag.split_whitespace().collect::<Vec<_>>().concat())
            // ?
            .take_while(|s| !s.is_empty())
        {
            match i.split_once('=').ok_or(ParseError::SyntaxError {
                reason: "tag syntax is `{tag}={value}`".to_string(),
            })? {
                ("v", p_version) => {
                    version = Some(Version::from_str(p_version).map_err(|e| {
                        ParseError::SyntaxError {
                            reason: format!("when parsing `version`, got: `{e}`"),
                        }
                    })?);
                }
                ("adkim", p_adkim) => {
                    adkim = p_adkim.parse().map_err(|e| ParseError::InvalidArgument {
                        reason: format!("invalid value for `adkim`: `{e}`"),
                    })?;
                }
                ("aspf", p_aspf) => {
                    aspf = p_aspf.parse().map_err(|e| ParseError::InvalidArgument {
                        reason: format!("invalid value for `aspf`: `{e}`"),
                    })?;
                }
                ("fo", p_fo) => {
                    failure_report_options = p_fo
                        .split(':')
                        .map(FailureReportOption::from_str)
                        .filter_map(Result::ok)
                        .collect::<Vec<_>>();
                }
                ("p", p_receiver_policy) => {
                    receiver_policy = Some(p_receiver_policy.parse().map_err(|e| {
                        ParseError::InvalidArgument {
                            reason: format!("invalid value for `p`: `{e}`"),
                        }
                    })?);
                }
                ("sp", p_receiver_policy_subdomain) => {
                    receiver_policy_subdomain =
                        Some(p_receiver_policy_subdomain.parse().map_err(|e| {
                            ParseError::InvalidArgument {
                                reason: format!("invalid value for `p`: `{e}`"),
                            }
                        })?);
                }
                ("pct", p_pct) => {
                    let i = p_pct
                        .parse::<i16>()
                        .map_err(|e| ParseError::InvalidArgument {
                            reason: format!("invalid value for `pct`: `{e}`"),
                        })?;

                    if i.clamp(0, 100) != i {
                        return Err(ParseError::InvalidArgument {
                            reason: format!(
                                "invalid value for `pct` ({i}): `must be between 0 and 100`"
                            ),
                        });
                    }

                    percentage = u8::try_from(i).expect("i16 is within u8 range");
                }
                ("rf", p_report_failure) => {
                    report_failure =
                        p_report_failure
                            .parse()
                            .map_err(|e| ParseError::InvalidArgument {
                                reason: format!("invalid value for `rf`: `{e}`"),
                            })?;
                }
                ("ri", p_report_interval) => {
                    report_interval = p_report_interval.parse::<u32>().map_err(|e| {
                        ParseError::InvalidArgument {
                            reason: format!("invalid value for `ri`: `{e}`"),
                        }
                    })?;
                }
                ("rua", p_report_aggregate_feedback) => {
                    report_aggregate_feedback = p_report_aggregate_feedback
                        .split(',')
                        .map(str::to_string)
                        .collect();
                }
                ("ruf", p_report_specific_message) => {
                    report_specific_message = p_report_specific_message
                        .split(',')
                        .map(str::to_string)
                        .collect();
                }
                // ignore unknown tag
                _ => continue,
            }
        }

        Ok(Self {
            version: version.ok_or(ParseError::MissingRequiredField {
                field: "v".to_string(),
            })?,
            adkim,
            aspf,
            failure_report_options,
            receiver_policy: receiver_policy.ok_or_else(|| ParseError::MissingRequiredField {
                field: "p".to_string(),
            })?,
            receiver_policy_subdomain,
            percentage,
            report_failure,
            report_interval,
            report_aggregate_feedback,
            report_specific_message,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn parse() {
        let record =
            "v=DMARC1; p=none; rua=mailto:d@rua.agari.com;ruf=mailto:d@ruf.agari.com;fo=1:s:d; adkim=s; aspf=r; sp=none; pct=50; rf=afrf; ri=86400";

        let record = Record::from_str(record).unwrap();
        println!("{record:#?}");

        assert_eq!(record.get_policy(), ReceiverPolicy::None.to_string());
    }

    #[test]
    fn alignment_strict() {
        let record = Record {
            version: Version::Dmarc1,
            adkim: AlignmentMode::Strict,
            aspf: AlignmentMode::Strict,
            failure_report_options: vec![FailureReportOption::All],
            receiver_policy: ReceiverPolicy::None,
            receiver_policy_subdomain: None,
            percentage: 100,
            report_failure: ReportFailure::AuthReportFailureFormat,
            report_interval: 0,
            report_aggregate_feedback: vec![],
            report_specific_message: vec![],
        };

        assert!(record.dkim_is_aligned("outlook.fr", "outlook.fr"));
        assert!(record.spf_is_aligned("outlook.fr", "outlook.fr"));
    }

    #[test]
    fn alignment_relaxed() {
        let record = Record {
            version: Version::Dmarc1,
            adkim: AlignmentMode::Relaxed,
            aspf: AlignmentMode::Relaxed,
            failure_report_options: vec![FailureReportOption::All],
            receiver_policy: ReceiverPolicy::None,
            receiver_policy_subdomain: None,
            percentage: 100,
            report_failure: ReportFailure::AuthReportFailureFormat,
            report_interval: 0,
            report_aggregate_feedback: vec![],
            report_specific_message: vec![],
        };

        assert!(record.dkim_is_aligned("subdomain.outlook.fr", "outlook.fr"));
        assert!(record.spf_is_aligned("subdomain.outlook.fr", "outlook.fr"));

        assert!(!record.dkim_is_aligned("toto", "outlook.fr"));
        assert!(!record.dkim_is_aligned("outlook.fr", "toto"));

        assert!(!record.spf_is_aligned("toto", "outlook.fr"));
        assert!(!record.spf_is_aligned("outlook.fr", "toto"));
    }

    mod error {
        use super::*;

        #[test]
        fn not_tag_based_syntax() {
            let _err = <Record as std::str::FromStr>::from_str("foobar").unwrap_err();
        }

        #[test]
        fn invalid_version() {
            let _err = <Record as std::str::FromStr>::from_str("v=DMARC2").unwrap_err();
        }

        #[test]
        fn invalid_adkim() {
            let _err = <Record as std::str::FromStr>::from_str("adkim=foo").unwrap_err();
        }

        #[test]
        fn invalid_aspf() {
            let _err = <Record as std::str::FromStr>::from_str("aspf=foo").unwrap_err();
        }

        #[test]
        fn invalid_policy() {
            let _err = <Record as std::str::FromStr>::from_str("p=foo").unwrap_err();
        }

        #[test]
        fn invalid_subdomain_policy() {
            let _err = <Record as std::str::FromStr>::from_str("sp=foo").unwrap_err();
        }

        #[test]
        fn invalid_pct() {
            let _err = <Record as std::str::FromStr>::from_str("pct=foo").unwrap_err();
        }

        #[test]
        fn invalid_pct_to_high() {
            let _err = <Record as std::str::FromStr>::from_str("pct=101").unwrap_err();
        }

        #[test]
        fn invalid_report_failure() {
            let _err = <Record as std::str::FromStr>::from_str("rf=foobar").unwrap_err();
        }

        #[test]
        fn invalid_report_interval() {
            let _err = <Record as std::str::FromStr>::from_str("ri=foobar").unwrap_err();
        }

        #[test]
        fn missing_version() {
            let _err = <Record as std::str::FromStr>::from_str("").unwrap_err();
        }

        #[test]
        fn missing_policy() {
            let _err = <Record as std::str::FromStr>::from_str("v=DMARC1").unwrap_err();
        }
    }
}
