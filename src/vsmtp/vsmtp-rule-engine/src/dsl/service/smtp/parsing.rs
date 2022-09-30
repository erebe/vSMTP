use crate::dsl::service::{deserialize_rhai_map, Parser, SmtpConnection};
use crate::{api::EngineResult, dsl::service::Service};
use lettre;

#[derive(Debug, serde::Deserialize)]
struct SmtpDelegatorParameters {
    /// The address to delegate the email to.
    address: std::net::SocketAddr,
    /// Timeout for the SMTP connection.
    #[serde(default = "default_timeout", with = "humantime_serde")]
    timeout: std::time::Duration,
}

#[derive(Debug, serde::Deserialize)]
struct SmtpParameters {
    /// Receiver socket.
    receiver: std::net::SocketAddr,
    /// Delegation parameters.
    delegator: SmtpDelegatorParameters,
}

const fn default_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(30)
}

pub struct SmtpParser;

impl Parser for SmtpParser {
    fn service_type(&self) -> &'static str {
        "smtp"
    }

    fn parse_service(&self, service: &str, parameters: rhai::Map) -> EngineResult<Service> {
        let parameters: SmtpParameters =
            deserialize_rhai_map(service, self.service_type(), parameters)?;

        Ok(Service::Smtp {
            delegator: SmtpConnection(std::sync::Arc::new(std::sync::Mutex::new(
                lettre::SmtpTransport::builder_dangerous(
                    parameters.delegator.address.ip().to_string(),
                )
                .port(parameters.delegator.address.port())
                .timeout(Some(parameters.delegator.timeout))
                .build(),
            ))),
            receiver: parameters.receiver,
        })
    }
}
