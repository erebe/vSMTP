# Stress tests for vSMTP

This folder contains a binary `vsmtp-stress` simulating heavy message traffic.

The program will instantiate `X` client on separated threads, each sending `Y` mails.\
If a client failed (code 5xx) to send emails, it will try to send a full payload later.

This program helps to monitor 3 characteristics :

* **Utilization**: The amount of time the system is actually doing useful work servicing a request.
* **Saturation**: When requests have to wait before being serviced.
* **Errors**: When things start to fail. (i.e. when queues are no longer able to accept any new requests)

## Usage

> All commands are run from the root of the repository.
> Do not forget to empty the queues between each runs.

### Generate a flamegraph

```sh
cargo build --bin vsmtp-stress --manifest-path=benchmarks/stress/Cargo.toml
CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --deterministic \
    --bin vsmtp -- -t 10s --no-daemon -c benchmarks/stress/vsmtp.stress.toml &
./benchmarks/stress/target/debug/vsmtp-stress
```

### Generate telemetries

```sh
cargo build --release --bin vsmtp
cargo build --bin vsmtp-stress --features telemetry --manifest-path=benchmarks/stress/Cargo.toml
jaeger-all-in-one & # (see <https://www.jaegertracing.io/docs/1.33/getting-started/>)
cargo run --release --bin vsmtp -- -t 10s --no-daemon -c benchmarks/stress/vsmtp.stress.toml &
./benchmarks/stress/target/debug/vsmtp-stress
```

### Measure CPU instructions

```sh
cargo build --bin vsmtp-stress --manifest-path=benchmarks/stress/Cargo.toml
./tools/instructions.sh
./benchmarks/stress/target/debug/vsmtp-stress
```
