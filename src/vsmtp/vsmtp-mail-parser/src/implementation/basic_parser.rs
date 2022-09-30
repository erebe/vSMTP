use crate::{Mail, MailParser, ParserResult, RawBody};

///
#[derive(Default)]
pub struct BasicParser;

impl MailParser for BasicParser {
    fn parse_sync(&mut self, raw: Vec<String>) -> ParserResult<either::Either<RawBody, Mail>> {
        let mut headers = Vec::<String>::new();
        let mut body = String::new();

        let mut stream = raw.iter();

        for line in stream.by_ref() {
            if line.is_empty() {
                break;
            }
            headers.push((*line).to_string());
        }

        for line in stream {
            body.push_str(line);
            body.push_str("\r\n");
        }

        Ok(either::Left(RawBody::new(headers, body)))
    }
}
