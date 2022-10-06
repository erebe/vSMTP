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
use crate::{api::DetailedMailContext, cli::args::Commands, GenericQueueManager, QueueID};

type Domain = String;

#[derive(Debug)]
struct Content {
    queue_id: QueueID,
    now: std::time::SystemTime,
    inner: Vec<anyhow::Result<DetailedMailContext>>,
    error_count: usize,
    result: std::collections::HashMap<Domain, MessageByLifetime>,
    empty_token: char,
    exists: bool,
}

type MessageByLifetime = std::collections::HashMap<u64, Vec<DetailedMailContext>>;

impl Content {
    fn lifetimes() -> Vec<u64> {
        (0..9)
            .into_iter()
            .scan(5, |state, _| {
                let out = *state;
                *state *= 2;
                Some(out)
            })
            .collect()
    }

    fn add_entry(&mut self, key: &str, mut values: Vec<DetailedMailContext>) {
        let mut out = MessageByLifetime::new();

        for lifetime in Self::lifetimes() {
            let split_index = itertools::partition(&mut values, |i| {
                self.now
                    .duration_since(i.modified_at)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    / 60
                    < lifetime
            });
            let next_values = values.split_off(split_index);

            if !values.is_empty() {
                out.entry(lifetime)
                    .and_modify(|v| v.extend(values.clone()))
                    .or_insert_with(|| values);
            }
            values = next_values;
        }
        out.insert(u64::MAX, values);

        assert!(!self.result.contains_key(key));
        self.result.insert(key.to_string(), out);
    }
}

impl std::fmt::Display for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        macro_rules! token_if_empty {
            ($t:expr, $e:expr) => {
                if $e != 0 {
                    $e.to_string()
                } else {
                    $t.to_string()
                }
            };
        }

        let lifetimes = Self::lifetimes();

        f.write_fmt(format_args!(
            "{:<10} has :",
            self.queue_id.to_string().to_uppercase(),
        ))?;

        if self.inner.is_empty() {
            f.write_str(if self.exists {
                "\t<EMPTY>"
            } else {
                "\t<MISSING>"
            })?;
        }

        if self.error_count != 0 {
            f.write_fmt(format_args!("\twith {} error", self.error_count))?;
        }

        f.write_str("\n")?;

        if self.inner.is_empty() {
            return Ok(());
        }

        f.write_fmt(format_args!("{:>25}", "T"))?;
        for i in &lifetimes {
            f.write_fmt(format_args!("{i:>5}"))?;
        }
        f.write_fmt(format_args!(
            "{max:>5}+",
            max = lifetimes.last().unwrap_or(&0)
        ))?;
        f.write_str("\n")?;

        f.write_fmt(format_args!(
            "{:>20}{:>5}",
            "TOTAL",
            token_if_empty!(
                self.empty_token,
                self.result.iter().fold(0, |sum, (_, values)| values
                    .iter()
                    .fold(sum, |sum, (_, m)| { sum + m.len() }))
            )
        ))?;

        let sum_where = |lifetime: u64| {
            self.result.iter().fold(0, |sum, (_, values)| {
                values
                    .iter()
                    .filter(|(l, _)| **l == lifetime)
                    .fold(sum, |sum, (_, m)| sum + m.len())
            })
        };

        for i in &lifetimes {
            f.write_fmt(format_args!(
                "{:>5}",
                token_if_empty!(self.empty_token, sum_where(*i))
            ))?;
        }
        f.write_fmt(format_args!(
            "{max:>5}",
            max = token_if_empty!(self.empty_token, sum_where(u64::MAX))
        ))?;
        f.write_str("\n")?;

        for (key, values) in &self.result {
            f.write_fmt(format_args!(
                "{key:>20}{:>5}",
                token_if_empty!(
                    self.empty_token,
                    values.iter().fold(0, |sum, (_, m)| sum + m.len())
                )
            ))?;

            for i in &lifetimes {
                f.write_fmt(format_args!(
                    "{:>5}",
                    token_if_empty!(self.empty_token, values.get(i).map_or(0, Vec::len))
                ))?;
            }
            f.write_fmt(format_args!(
                "{max:>5}",
                max = token_if_empty!(self.empty_token, values.get(&u64::MAX).map_or(0, Vec::len))
            ))?;
            f.write_str("\n")?;
        }

        Ok(())
    }
}

impl Commands {
    pub(crate) async fn show<OUT: std::io::Write + Send + Sync>(
        queues: Vec<QueueID>,
        queue_manager: std::sync::Arc<impl GenericQueueManager + Send + Sync>,
        empty_token: char,
        output: &mut OUT,
    ) -> anyhow::Result<()> {
        for q in &queues {
            let mut content = Content {
                now: std::time::SystemTime::now(),
                queue_id: q.clone(),
                inner: vec![],
                error_count: 0,
                result: std::collections::HashMap::new(),
                empty_token,
                exists: true,
            };

            match queue_manager.list(q).await {
                Ok(list) if !list.is_empty() => {
                    for i in list {
                        content.inner.push(match i {
                            Ok(msg_id) => queue_manager.get_detailed_ctx(q, &msg_id).await,
                            Err(e) => Err(e),
                        });
                    }

                    let split_index = itertools::partition(&mut content.inner, Result::is_ok);

                    let errors = content.inner.split_off(split_index);
                    content.error_count = errors.len();

                    let mut valid_entries = content
                        .inner
                        .iter()
                        .map(|i| i.as_ref().unwrap())
                        .cloned()
                        .collect::<Vec<_>>();

                    valid_entries
                        .sort_by(|a, b| Ord::cmp(&a.ctx.envelop.helo, &b.ctx.envelop.helo));

                    for (key, values) in
                        &itertools::Itertools::group_by(valid_entries.into_iter(), |i| {
                            i.ctx.envelop.helo.clone()
                        })
                    {
                        content.add_entry(&key, values.into_iter().collect::<Vec<_>>());
                    }
                }
                Ok(_) => {}
                Err(_) => {
                    content.exists = false;
                }
            }
            output.write_fmt(format_args!("{content}"))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vsmtp_test::config::{local_ctx, local_msg, local_test};

    #[tokio::test(flavor = "multi_thread")]
    async fn working_and_delivery_empty() {
        let mut output = vec![];

        let config = std::sync::Arc::new(local_test());
        let queue_manager = crate::temp::QueueManager::init(config).unwrap();

        Commands::show(
            vec![QueueID::Working, QueueID::Deliver],
            queue_manager,
            '.',
            &mut output,
        )
        .await
        .unwrap();

        pretty_assertions::assert_eq!(
            std::str::from_utf8(&output).unwrap(),
            ["WORKING    has :\t<EMPTY>\n", "DELIVER    has :\t<EMPTY>\n",].concat(),
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn all_empty() {
        let mut output = vec![];

        let config = std::sync::Arc::new(local_test());
        let queue_manager = crate::temp::QueueManager::init(config).unwrap();

        Commands::show(
            <QueueID as strum::IntoEnumIterator>::iter()
                .filter(|i| !matches!(i, QueueID::Quarantine { .. }))
                .collect::<Vec<_>>(),
            queue_manager,
            '.',
            &mut output,
        )
        .await
        .unwrap();

        pretty_assertions::assert_eq!(
            std::str::from_utf8(&output).unwrap(),
            [
                "WORKING    has :\t<EMPTY>\n",
                "DELIVER    has :\t<EMPTY>\n",
                "DELEGATED  has :\t<EMPTY>\n",
                "DEFERRED   has :\t<EMPTY>\n",
                "DEAD       has :\t<EMPTY>\n"
            ]
            .concat(),
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn all_missing() {
        let mut output = vec![];

        let config = std::sync::Arc::new(local_test());
        let queue_manager = crate::temp::QueueManager::init(config.clone()).unwrap();

        let queues = <QueueID as strum::IntoEnumIterator>::iter()
            .filter(|i| !matches!(i, QueueID::Quarantine { .. }))
            .collect::<Vec<_>>();

        std::fs::remove_dir_all(queue_manager.tempdir.path()).unwrap();

        Commands::show(queues, queue_manager, '.', &mut output)
            .await
            .unwrap();

        pretty_assertions::assert_eq!(
            std::str::from_utf8(&output).unwrap(),
            [
                "WORKING    has :\t<MISSING>\n",
                "DELIVER    has :\t<MISSING>\n",
                "DELEGATED  has :\t<MISSING>\n",
                "DEFERRED   has :\t<MISSING>\n",
                "DEAD       has :\t<MISSING>\n"
            ]
            .concat(),
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_error() {
        let mut output = vec![];

        let config = std::sync::Arc::new(local_test());

        let queue_manager = crate::temp::QueueManager::init(config.clone()).unwrap();

        std::fs::write(
            format!(
                "{root}/{spool}/working/00.json",
                root = queue_manager.tempdir.path().display(),
                spool = config.server.queues.dirpath.display(),
            ),
            "foobar",
        )
        .unwrap();

        Commands::show(
            <QueueID as strum::IntoEnumIterator>::iter()
                .filter(|i| !matches!(i, QueueID::Quarantine { .. }))
                .collect::<Vec<_>>(),
            queue_manager,
            '.',
            &mut output,
        )
        .await
        .unwrap();

        pretty_assertions::assert_eq!(
            std::str::from_utf8(&output).unwrap(),
            [
                "WORKING    has :\t<EMPTY>\twith 1 error\n",
                "DELIVER    has :\t<EMPTY>\n",
                "DELEGATED  has :\t<EMPTY>\n",
                "DEFERRED   has :\t<EMPTY>\n",
                "DEAD       has :\t<EMPTY>\n"
            ]
            .concat(),
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[function_name::named]
    async fn dead_with_one() {
        let mut output = vec![];

        let config = std::sync::Arc::new(local_test());

        let queue_manager = crate::temp::QueueManager::init(config).unwrap();

        let msg = local_msg();
        let mut ctx = local_ctx();
        ctx.metadata.message_id = Some(function_name!().to_string());
        queue_manager
            .write_both(&QueueID::Dead, &ctx, &msg)
            .await
            .unwrap();

        Commands::show(
            <QueueID as strum::IntoEnumIterator>::iter()
                .filter(|i| !matches!(i, QueueID::Quarantine { .. }))
                .collect::<Vec<_>>(),
            queue_manager,
            '.',
            &mut output,
        )
        .await
        .unwrap();

        pretty_assertions::assert_eq!(
            std::str::from_utf8(&output).unwrap(),
            [
                "WORKING    has :\t<EMPTY>\n",
                "DELIVER    has :\t<EMPTY>\n",
                "DELEGATED  has :\t<EMPTY>\n",
                "DEFERRED   has :\t<EMPTY>\n",
                "DEAD       has :\n",
                "                        T    5   10   20   40   80  160  320  640 1280 1280+\n",
                "               TOTAL    1    1    .    .    .    .    .    .    .    .    .\n",
                "client.testserver.com    1    1    .    .    .    .    .    .    .    .    .\n",
            ]
            .concat(),
        );
    }
}
