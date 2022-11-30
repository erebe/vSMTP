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

pub fn from_string(input: &str) -> anyhow::Result<rustls::Certificate> {
    let path = std::path::Path::new(&input);
    anyhow::ensure!(
        path.exists(),
        format!("certificate path does not exists: '{}'", path.display())
    );
    let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);

    let pem = rustls_pemfile::certs(&mut reader)?
        .into_iter()
        .map(rustls::Certificate)
        .collect::<Vec<_>>();

    pem.first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("certificate path is valid but empty: '{}'", path.display()))
}

#[cfg(test)]
mod tests {
    use crate::field::SecretFile;
    use std::io::Write;
    use vsmtp_test::get_tls_file;

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct S {
        v: SecretFile<rustls::Certificate>,
    }

    #[test]
    fn basic() {
        let _droppable = std::fs::DirBuilder::new().create("./tmp");

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open("./tmp/crt")
            .unwrap();
        file.write_all(get_tls_file::get_certificate().as_bytes())
            .unwrap();

        serde_json::from_str::<S>(r#"{"v": "./tmp/crt"}"#).unwrap();
    }

    #[test]
    fn not_a_string() {
        serde_json::from_str::<S>(r#"{"v": 10}"#).unwrap_err();
    }

    #[test]
    fn not_valid_path() {
        serde_json::from_str::<S>(r#"{"v": "foobar"}"#).unwrap_err();
    }
}
