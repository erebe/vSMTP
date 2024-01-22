use crate::{Mail, MailParser, ParserResult, RawBody};

///
#[derive(Default)]
pub struct BasicParser;

impl MailParser for BasicParser {
    fn parse_sync(&mut self, raw: Vec<Vec<u8>>) -> ParserResult<either::Either<RawBody, Mail>> {
        let mut headers = Vec::<String>::new();
        let mut body = String::new();

        let mut stream = raw.iter();

        for line in stream.by_ref() {
            if line == b"\r\n" {
                break;
            }
            if !line.first().map_or(false, |c| [b' ', b'\t'].contains(c)) && !line.contains(&b':') {
                body.push_str(String::from_utf8_lossy(line).as_ref());
                break;
            }
            headers.push(String::from_utf8_lossy(line).to_string());
        }

        for line in stream {
            body.push_str(String::from_utf8_lossy(line).as_ref());
        }

        Ok(either::Left(RawBody::new(headers, body)))
    }
}
