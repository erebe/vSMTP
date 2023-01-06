# Benchmarks

This directory contains multiple configuration to mesure the performances of vSMTP and compare them to other software.

* **stress**: Run vsmtp under heavy load with random tls settings, port and authentication coming from the client. Supports telemetry using the [opentelemetry crate](https://crates.io/crates/opentelemetry).
* **hold**: Compare the performances of vSMTP and Postfix when holding any incoming message.
