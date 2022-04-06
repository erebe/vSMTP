use crate::Config;

#[test]
fn parse() {
    let toml = include_str!("../../../../examples/config/tls.toml");
    pretty_assertions::assert_eq!(
        Config::from_toml(toml).unwrap(),
        Config::builder()
            .with_version_str("<1.0.0")
            .unwrap()
            .with_server_name("testserver.com")
            .with_default_system()
            .with_ipv4_localhost()
            .with_default_logs_settings()
            .with_default_delivery()
            .with_safe_tls_config(
                "../examples/config/tls/certificate.crt",
                "../examples/config/tls/private_key.key"
            )
            .unwrap()
            .with_sni_entry(
                "testserver2.com",
                "../examples/config/tls/certificate.crt",
                "../examples/config/tls/private_key.key"
            )
            .unwrap()
            .with_sni_entry(
                "testserver3.com",
                "../examples/config/tls/certificate.crt",
                "../examples/config/tls/private_key.key"
            )
            .unwrap()
            .with_default_smtp_options()
            .with_default_smtp_error_handler()
            .with_default_smtp_codes()
            .without_auth()
            .with_default_app()
            .with_default_vsl_settings()
            .with_default_app_logs()
            .without_services()
            .with_system_dns()
            .validate()
            .unwrap()
    );
}