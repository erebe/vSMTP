/// Create a new engine instance with the current plugin registered.
///
/// NOTE: use the `throw` rhai keyword to make the test fail.
#[cfg(feature = "testing")]
#[macro_export]
macro_rules! eval_with_plugin {
    ($test:ident, $plugin:expr, $script:tt) => {
        #[test]
        pub fn $test() {
            // TODO: inject user's engine configuration.
            let mut engine = vsmtp_plugins::rhai::Engine::new();

            vsmtp_plugins::plugins::vsl::native::Native::register(
                &$plugin,
                vsmtp_plugins::plugins::vsl::native::Builder::new(&mut engine),
            )
            .expect("registering vsl plugin failed");

            engine.set_fast_operators(false);

            engine
                // TODO: handle scripts + script paths.
                .run(stringify!($script))
                .expect("failed to evaluate script");
        }
    };
}
