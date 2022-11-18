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
            headers.push(String::from_utf8(line.clone()).expect("todo: handle non utf8"));
        }

        for line in stream {
            body.push_str(std::str::from_utf8(line).expect("todo: handle non utf8"));
        }

        Ok(either::Left(RawBody::new(headers, body)))
    }
}
