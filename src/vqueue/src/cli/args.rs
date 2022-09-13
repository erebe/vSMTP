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
use crate::QueueID;

///
#[derive(clap::Parser)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[clap(about, version, author)]
pub struct Args {
    /// Print the version and exit.
    #[clap(short, long, action)]
    pub version: bool,

    /// Path of the vSMTP configuration file (toml format)
    #[clap(short, long, action)]
    pub config: Option<String>,

    ///
    #[clap(subcommand)]
    pub command: Option<Commands>,
}

///
#[derive(clap::Subcommand)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum Commands {
    /// Show the content of the given queue(s)
    Show {
        /// List of queues to print
        #[clap(value_parser)]
        queues: Vec<QueueID>,
        /// Character to print if the field is empty
        #[clap(short, long, action, default_value = "0")]
        empty_token: char,
    },
    /// Operate action to a given message
    Msg {
        /// ID of the concerned message
        #[clap(value_parser)]
        msg: String,
        ///
        #[clap(subcommand)]
        command: MessageCommand,
    },
}

///
#[derive(Clone, clap::Subcommand)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum MessageCommand {
    /// Print the content of the message
    Show {
        /// Format of the output
        #[clap(arg_enum, value_parser, default_value = "json")]
        format: MessageShowFormat,
    },
    /// Move the message to the given queue
    Move {
        ///
        #[clap(value_parser)]
        queue: QueueID,
    },
    /// Remove the message from the filesystem
    Remove {
        /// If true, do not ask to confirm the deletion
        #[clap(short, long, value_parser)]
        yes: bool,
    },
    /// Re-introduce the message in the delivery system
    ReRun {},
}

///
#[derive(Clone, clap::ArgEnum)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum MessageShowFormat {
    /// Message's body as .eml (bytes between DATA and \r\n.\r\n)
    Eml,
    /// Complete mail context
    Json,
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn arg_show_version() {
        assert_eq!(
            Args {
                version: true,
                config: None,
                command: None,
            },
            <Args as clap::StructOpt>::try_parse_from(&["", "--version"]).unwrap()
        );
    }

    #[test]
    fn arg_show_queue() {
        assert_eq!(
            Args {
                version: false,
                config: None,
                command: Some(Commands::Show {
                    queues: vec![],
                    empty_token: '0'
                })
            },
            <Args as clap::StructOpt>::try_parse_from(&["", "show"]).unwrap()
        );

        assert_eq!(
            Args {
                version: false,
                config: None,
                command: Some(Commands::Show {
                    queues: vec![QueueID::Dead],
                    empty_token: '0'
                })
            },
            <Args as clap::StructOpt>::try_parse_from(&["", "show", "dead"]).unwrap()
        );

        assert_eq!(
            Args {
                version: false,
                config: None,
                command: Some(Commands::Show {
                    queues: vec![],
                    empty_token: '.'
                })
            },
            <Args as clap::StructOpt>::try_parse_from(&["", "show", "-e", "."]).unwrap()
        );

        assert_eq!(
            Args {
                version: false,
                config: None,
                command: Some(Commands::Show {
                    queues: vec![QueueID::Dead, QueueID::Deliver],
                    empty_token: '0'
                })
            },
            <Args as clap::StructOpt>::try_parse_from(&["", "show", "dead", "deliver"]).unwrap()
        );
    }

    #[test]
    fn arg_show_message() {
        assert_eq!(
            Args {
                version: false,

                config: None,
                command: Some(Commands::Msg {
                    msg: "foobar".to_string(),
                    command: MessageCommand::Show {
                        format: MessageShowFormat::Json
                    }
                })
            },
            <Args as clap::StructOpt>::try_parse_from(&["", "msg", "foobar", "show"]).unwrap()
        );

        assert_eq!(
            Args {
                version: false,

                config: None,
                command: Some(Commands::Msg {
                    msg: "foobar".to_string(),
                    command: MessageCommand::Show {
                        format: MessageShowFormat::Json
                    }
                })
            },
            <Args as clap::StructOpt>::try_parse_from(&["", "msg", "foobar", "show", "json"])
                .unwrap()
        );

        assert_eq!(
            Args {
                version: false,

                config: None,
                command: Some(Commands::Msg {
                    msg: "foobar".to_string(),
                    command: MessageCommand::Show {
                        format: MessageShowFormat::Eml
                    }
                })
            },
            <Args as clap::StructOpt>::try_parse_from(&["", "msg", "foobar", "show", "eml"])
                .unwrap()
        );
    }

    #[test]
    fn arg_move_message() {
        assert_eq!(
            Args {
                version: false,

                config: None,
                command: Some(Commands::Msg {
                    msg: "foobar".to_string(),
                    command: MessageCommand::Move {
                        queue: QueueID::Dead
                    }
                })
            },
            <Args as clap::StructOpt>::try_parse_from(&["", "msg", "foobar", "move", "dead"])
                .unwrap()
        );
    }

    #[test]
    fn arg_remove_message() {
        assert_eq!(
            Args {
                version: false,

                config: None,
                command: Some(Commands::Msg {
                    msg: "foobar".to_string(),
                    command: MessageCommand::Remove { yes: false }
                })
            },
            <Args as clap::StructOpt>::try_parse_from(&["", "msg", "foobar", "remove"]).unwrap()
        );

        assert_eq!(
            Args {
                version: false,

                config: None,
                command: Some(Commands::Msg {
                    msg: "foobar".to_string(),
                    command: MessageCommand::Remove { yes: true }
                })
            },
            <Args as clap::StructOpt>::try_parse_from(&["", "msg", "foobar", "remove", "--yes"])
                .unwrap()
        );
    }
}
