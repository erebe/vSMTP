#![no_main]
use libfuzzer_sys::fuzz_target;
use vsmtp_mail_parser::{MailMimeParser, MailParser};

fuzz_target!(|data: &[u8]| {
    let _ = std::str::from_utf8(data).map(|data| {
        MailMimeParser::default().parse_sync(
            data.lines()
                .map(|l| l.as_bytes().to_vec())
                .collect::<Vec<_>>(),
        )
    });
});
