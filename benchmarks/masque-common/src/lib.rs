//! Shared controller logic for the MASQUE system benchmarks.
//!
//! The benchmarks run on the controller host (Alice) and drive a second host (Bob) over
//! SSH, mirroring the GotaTun throughput benchmark. The proxy binaries under test are the
//! `mullvad-masque-proxy` examples, built from this repository checkout and deployed to
//! Bob when needed.

use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use benchy_lib::Unit;
use benchy_runner::{
    BenchmarkDefinition, MachineLock, MeasurementDefinition, Recorder, checked_output,
    default_output_path,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader, Lines},
    net::TcpStream,
    process::{Child, Command},
    time::{sleep, timeout},
};

const READY_MARKER: &str = "Listening on";
const READY_TIMEOUT: Duration = Duration::from_secs(20);
const PROBE_ATTEMPTS: usize = 10;
const PROBE_INTERVAL: Duration = Duration::from_millis(500);
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

const SENDER_THROUGHPUT: MeasurementDefinition = MeasurementDefinition {
    id: "throughput.sender",
    label: "Sender throughput",
    unit: Unit::BitsPerSecond,
};
const RECEIVER_THROUGHPUT: MeasurementDefinition = MeasurementDefinition {
    id: "throughput.receiver",
    label: "Receiver throughput",
    unit: Unit::BitsPerSecond,
};
const UDP_JITTER: MeasurementDefinition = MeasurementDefinition {
    id: "udp.jitter",
    label: "UDP jitter",
    unit: Unit::Seconds,
};
const UDP_LOST_PERCENT: MeasurementDefinition = MeasurementDefinition {
    id: "udp.lost_percent",
    label: "UDP packet loss",
    unit: Unit::Percent,
};

/// Run one of the UDP-over-MASQUE benchmarks with the given iperf3 datagram length.
///
/// Datagrams larger than the MASQUE client MTU exercise the fragmentation path.
pub async fn run_udp_benchmark(
    definition: BenchmarkDefinition,
    datagram_length: u16,
) -> Result<()> {
    let mut recorder = Recorder::new(definition, default_output_path(definition.name)).await;
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            recorder.failure(&error).await?;
            return Err(error);
        }
    };
    recorder.parameter("duration_seconds", config.duration);
    recorder.parameter("datagram_length", datagram_length);
    recorder.parameter("masque_mtu", config.masque_mtu);

    match udp_controller(&config, datagram_length)
        .await
        .and_then(validate_udp_result)
    {
        Ok(result) => {
            if let Some(sent) = result.end.sent() {
                recorder.measurement(SENDER_THROUGHPUT, sent.bits_per_second)?;
            }
            if let Some(received) = result.end.received() {
                recorder.measurement(RECEIVER_THROUGHPUT, received.bits_per_second)?;
                if let Some(jitter_ms) = received.jitter_ms {
                    recorder.measurement(UDP_JITTER, jitter_ms / 1000.0)?;
                }
                if let Some(lost_percent) = received.lost_percent {
                    recorder.measurement(UDP_LOST_PERCENT, lost_percent)?;
                }
            }
            recorder.success().await
        }
        Err(error) => {
            recorder.failure(&error).await?;
            Err(error)
        }
    }
}

fn validate_udp_result(result: iperf_udp::UdpOutput) -> Result<iperf_udp::UdpOutput> {
    ensure!(
        result.end.received().is_some(),
        "iperf3 UDP output did not contain a receiver summary"
    );
    Ok(result)
}

async fn udp_controller(config: &Config, datagram_length: u16) -> Result<iperf_udp::UdpOutput> {
    let _machine_lock = MachineLock::acquire("/tmp/benchy.lock")?;

    // The MASQUE client forwards UDP datagrams to the iperf3 server on Alice.
    let mut proxies = MasqueProxies::start(
        config,
        SocketAddr::new(config.alice_address, config.iperf_port),
    )
    .await?;
    let result = udp_run(config, datagram_length).await;
    proxies.stop().await;
    result
}

async fn udp_run(config: &Config, datagram_length: u16) -> Result<iperf_udp::UdpOutput> {
    let mut iperf_server = iperf_server(config.alice_address, config.iperf_port).await?;
    let result = async {
        // The MASQUE proxy only forwards UDP, so iperf3's TCP control channel is
        // relayed directly to the server with socat.
        let mut socat = RemoteProcess::spawn(
            &config.peer,
            "socat",
            &[
                format!("TCP4-LISTEN:{},fork,reuseaddr", config.masque_client_port),
                format!("TCP:{}:{}", config.alice_address, config.iperf_port),
            ],
            None,
        )
        .await?;

        let result = async {
            wait_remote_tcp(&config.peer, "127.0.0.1", config.masque_client_port).await?;
            let iperf_command = remote_command(
                "iperf3",
                &[
                    "--json".to_owned(),
                    "--udp".to_owned(),
                    "--client".to_owned(),
                    "127.0.0.1".to_owned(),
                    "--port".to_owned(),
                    config.masque_client_port.to_string(),
                    "--time".to_owned(),
                    config.duration.to_string(),
                    "--length".to_owned(),
                    datagram_length.to_string(),
                    "--bandwidth".to_owned(),
                    "10G".to_owned(),
                ],
            );
            let output = checked_output("ssh", [&config.peer, &iperf_command]).await?;
            iperf_udp::parse(&output)
        }
        .await;
        socat.stop().await;
        result
    }
    .await;
    iperf_server.stop().await;
    result
}

/// Environment-driven benchmark configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub peer: String,
    pub alice_address: IpAddr,
    pub bob_address: IpAddr,
    pub masque_server_port: u16,
    pub masque_client_port: u16,
    pub iperf_port: u16,
    pub wireguard_port: u16,
    pub interface: String,
    pub duration: u64,
    pub masque_mtu: u16,
    pub tunnel_mtu: u16,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            peer: env_value("BENCHY_PEER", "mole@10.0.0.2"),
            alice_address: env_value("BENCHY_ALICE_ADDRESS", "10.0.0.1").parse()?,
            bob_address: env_value("BENCHY_BOB_ADDRESS", "10.0.0.2").parse()?,
            masque_server_port: env_value("BENCHY_MASQUE_SERVER_PORT", "9020").parse()?,
            masque_client_port: env_value("BENCHY_MASQUE_CLIENT_PORT", "9010").parse()?,
            iperf_port: env_value("BENCHY_IPERF_PORT", "9030").parse()?,
            wireguard_port: env_value("BENCHY_WIREGUARD_PORT", "51821").parse()?,
            interface: env_value("BENCHY_INTERFACE", "bench0"),
            duration: env_value("BENCHY_DURATION", "30").parse()?,
            masque_mtu: env_value("BENCHY_MASQUE_MTU", "1280").parse()?,
            tunnel_mtu: env_value("BENCHY_TUNNEL_MTU", "1280").parse()?,
        })
    }

    pub fn masque_server_bind(&self) -> SocketAddr {
        SocketAddr::new(self.alice_address, self.masque_server_port)
    }
}

/// The MASQUE server on Alice and the MASQUE client on Bob.
pub struct MasqueProxies {
    peer: String,
    remote_dir: String,
    server: LocalProcess,
    client: RemoteProcess,
}

impl MasqueProxies {
    /// Builds the proxy examples from this checkout, deploys the client to Bob, and starts
    /// both proxies. `target_addr` is the server-side forwarding destination, as resolved
    /// by the server on Alice.
    pub async fn start(config: &Config, target_addr: SocketAddr) -> Result<Self> {
        let examples = build_masque_examples().await?;
        let remote_dir = scratch_dir_name();
        if let Err(error) = deploy_client(&config.peer, &examples.client, &remote_dir).await {
            remove_remote_dir(&config.peer, &remote_dir).await;
            return Err(error);
        }

        let mut server = match LocalProcess::spawn(
            &examples.server,
            &[
                "--cert-path".to_owned(),
                examples.cert.to_string_lossy().into_owned(),
                "--key-path".to_owned(),
                examples.key.to_string_lossy().into_owned(),
                "--bind-addr".to_owned(),
                config.masque_server_bind().to_string(),
            ],
            Some(READY_MARKER),
        )
        .await
        {
            Ok(server) => server,
            Err(error) => {
                remove_remote_dir(&config.peer, &remote_dir).await;
                return Err(error);
            }
        };

        let remote_client = format!("{remote_dir}/masque-client");
        let client = RemoteProcess::spawn(
            &config.peer,
            &remote_client,
            &[
                "--server-addr".to_owned(),
                config.masque_server_bind().to_string(),
                "--server-hostname".to_owned(),
                "example.org".to_owned(),
                "--bind-addr".to_owned(),
                format!("127.0.0.1:{}", config.masque_client_port),
                "--mtu".to_owned(),
                config.masque_mtu.to_string(),
                "--target-addr".to_owned(),
                target_addr.to_string(),
            ],
            Some(READY_MARKER),
        )
        .await;
        let mut client = match client {
            Ok(client) => client,
            Err(error) => {
                server.stop().await;
                remove_remote_dir(&config.peer, &remote_dir).await;
                return Err(error);
            }
        };

        // The client connects immediately after reporting readiness; a failed connection
        // exits the process right away.
        sleep(Duration::from_millis(500)).await;
        if let Err(error) = client.check_alive().await {
            client.stop().await;
            server.stop().await;
            remove_remote_dir(&config.peer, &remote_dir).await;
            return Err(error);
        }

        Ok(Self {
            peer: config.peer.clone(),
            remote_dir,
            server,
            client,
        })
    }

    pub async fn stop(&mut self) {
        self.client.stop().await;
        self.server.stop().await;
        remove_remote_dir(&self.peer, &self.remote_dir).await;
    }
}

struct MasqueExamples {
    server: PathBuf,
    client: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

fn app_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Builds the `mullvad-masque-proxy` example binaries from this repository checkout.
async fn build_masque_examples() -> Result<MasqueExamples> {
    let root = app_root();
    checked_output(
        "cargo",
        [
            "build".to_owned(),
            "--release".to_owned(),
            "--locked".to_owned(),
            "--manifest-path".to_owned(),
            root.join("Cargo.toml").to_string_lossy().into_owned(),
            "--package".to_owned(),
            "mullvad-masque-proxy".to_owned(),
            "--example".to_owned(),
            "masque-server".to_owned(),
            "--example".to_owned(),
            "masque-client".to_owned(),
        ],
    )
    .await
    .context("failed to build the mullvad-masque-proxy examples")?;

    let tests = root.join("mullvad-masque-proxy/tests");
    let binaries = root.join("target/release/examples");
    Ok(MasqueExamples {
        server: binaries.join("masque-server"),
        client: binaries.join("masque-client"),
        cert: tests.join("test.crt"),
        key: tests.join("test.key"),
    })
}

async fn deploy_client(peer: &str, client: &Path, remote_dir: &str) -> Result<()> {
    checked_output(
        "ssh",
        [
            peer,
            &format!(
                "mkdir -p {dir} && chmod 700 {dir}",
                dir = shell_quote(remote_dir)
            ),
        ],
    )
    .await?;
    checked_output(
        "scp",
        [
            client.as_os_str(),
            std::ffi::OsStr::new(&format!("{peer}:{remote_dir}/masque-client")),
        ],
    )
    .await?;
    let remote_executable = shell_quote(&format!("{remote_dir}/masque-client"));
    checked_output("ssh", [peer, &format!("chmod 755 {remote_executable}")]).await?;
    Ok(())
}

async fn remove_remote_dir(peer: &str, remote_dir: &str) {
    let _ = checked_output(
        "ssh",
        [peer, &format!("rm -rf -- {}", shell_quote(remote_dir))],
    )
    .await;
}

/// Starts an iperf3 server bound to the given address.
pub async fn iperf_server(bind: IpAddr, port: u16) -> Result<LocalProcess> {
    LocalProcess::spawn(
        "iperf3",
        &[
            "--server".to_owned(),
            "--bind".to_owned(),
            bind.to_string(),
            "--port".to_owned(),
            port.to_string(),
        ],
        None,
    )
    .await
}

/// A process running on the controller host.
pub struct LocalProcess {
    child: Child,
}

impl LocalProcess {
    /// Spawns a process and optionally waits for a readiness marker in its stderr logs.
    /// Output pipes are drained in the background to keep them from filling up.
    pub async fn spawn(
        program: impl AsRef<Path>,
        args: &[String],
        ready_marker: Option<&str>,
    ) -> Result<Self> {
        let program = program.as_ref();
        let mut child = Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(if ready_marker.is_some() {
                Stdio::piped()
            } else {
                Stdio::inherit()
            })
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("failed to start {}", program.display()))?;
        let stdout = child
            .stdout
            .take()
            .context("local process stdout was not captured")?;
        let lines = BufReader::new(stdout).lines();
        drain_remaining(lines, &program.to_string_lossy());
        if let Some(marker) = ready_marker {
            let stderr = child
                .stderr
                .take()
                .context("local process stderr was not captured")?;
            let mut lines = BufReader::new(stderr).lines();
            wait_for_marker_lines(&mut lines, marker, &program.to_string_lossy())
                .await
                .with_context(|| format!("{} failed to start", program.display()))?;
            drain_remaining(lines, &program.to_string_lossy());
        }
        Ok(Self { child })
    }

    pub async fn stop(&mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}

/// A process running on the peer host, started over SSH.
pub struct RemoteProcess {
    peer: String,
    pid: u32,
    child: Child,
}

impl RemoteProcess {
    /// Runs `sh -c 'echo $$; exec program args'` on the peer and records the reported
    /// process ID so the process can be stopped later. When `ready_marker` is given,
    /// waits for it in the process stderr logs.
    pub async fn spawn(
        peer: &str,
        program: &str,
        args: &[String],
        ready_marker: Option<&str>,
    ) -> Result<Self> {
        let inner = format!("echo $$; exec {}", remote_command(program, args));
        let remote = format!("sh -c {}", shell_quote(&inner));
        let mut child = Command::new("ssh")
            .arg(peer)
            .arg(remote)
            .stdout(Stdio::piped())
            .stderr(if ready_marker.is_some() {
                Stdio::piped()
            } else {
                Stdio::inherit()
            })
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("failed to start {program} on the peer"))?;
        let stdout = child
            .stdout
            .take()
            .context("remote process stdout was not captured")?;

        let mut lines = BufReader::new(stdout).lines();
        let pid = timeout(READY_TIMEOUT, async {
            let line = lines
                .next_line()
                .await
                .context("failed to read the remote process ID")?
                .context("the remote shell exited before starting the process")?;
            line.trim()
                .parse::<u32>()
                .context("the remote shell reported an invalid process ID")
        })
        .await
        .context("timed out waiting for the remote process ID")??;

        drain_remaining(lines, program);
        let mut process = Self {
            peer: peer.to_owned(),
            pid,
            child,
        };

        if let Some(marker) = ready_marker {
            let stderr = process
                .child
                .stderr
                .take()
                .context("remote process stderr was not captured")?;
            let mut lines = BufReader::new(stderr).lines();
            if let Err(error) = wait_for_marker_lines(&mut lines, marker, program).await {
                process.stop().await;
                return Err(error)
                    .with_context(|| format!("{program} on the peer failed to start"));
            }
            drain_remaining(lines, program);
        }

        Ok(process)
    }

    pub async fn check_alive(&mut self) -> Result<()> {
        match self.child.try_wait() {
            Ok(None) => Ok(()),
            Ok(Some(status)) => bail!("the peer process exited with {status}"),
            Err(error) => Err(error).context("failed to inspect the peer process"),
        }
    }

    pub async fn stop(&mut self) {
        let command = remote_command("kill", &[self.pid.to_string()]);
        let _ = checked_output("ssh", [self.peer.as_str(), &command]).await;
        let _ = self.child.wait().await;
    }
}

/// Waits until a TCP port on the peer accepts connections, using bash's `/dev/tcp`.
pub async fn wait_remote_tcp(peer: &str, address: &str, port: u16) -> Result<()> {
    let probe = remote_command(
        "timeout",
        &[
            "2".to_owned(),
            "bash".to_owned(),
            "-c".to_owned(),
            format!("</dev/tcp/{address}/{port}"),
        ],
    );
    for _ in 0..PROBE_ATTEMPTS {
        if checked_output("ssh", [peer, &probe]).await.is_ok() {
            return Ok(());
        }
        sleep(PROBE_INTERVAL).await;
    }
    bail!("the peer did not accept TCP connections on {address}:{port}");
}

/// Waits until a local TCP port accepts connections.
pub async fn wait_local_tcp(address: SocketAddr) -> Result<()> {
    for _ in 0..PROBE_ATTEMPTS {
        if timeout(PROBE_TIMEOUT, TcpStream::connect(address))
            .await
            .is_ok_and(|connection| connection.is_ok())
        {
            return Ok(());
        }
        sleep(PROBE_INTERVAL).await;
    }
    bail!("nothing accepted TCP connections on {address}");
}

/// Waits until the peer can reach the given tunnel address over ICMP.
pub async fn wait_for_tunnel(peer: &str, destination: Ipv4Addr) -> Result<()> {
    let command = remote_command(
        "ping",
        &[
            "-c".to_owned(),
            "1".to_owned(),
            "-W".to_owned(),
            "1".to_owned(),
            destination.to_string(),
        ],
    );
    for _ in 0..PROBE_ATTEMPTS {
        if checked_output("ssh", [peer, &command]).await.is_ok() {
            return Ok(());
        }
        sleep(PROBE_INTERVAL).await;
    }
    bail!("the tunnel to {destination} did not become ready");
}

/// Writes a file on the peer by piping its contents over SSH.
pub async fn remote_write_file(peer: &str, path: &str, contents: &str) -> Result<()> {
    let mut child = Command::new("ssh")
        .arg(peer)
        .arg(format!("umask 077; cat > {}", shell_quote(path)))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to write {path} on the peer"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(contents.as_bytes())
            .await
            .with_context(|| format!("failed to send {path} to the peer"))?;
    }
    let output = child
        .wait_with_output()
        .await
        .with_context(|| format!("failed to write {path} on the peer"))?;
    if !output.status.success() {
        bail!("failed to write {path} on the peer: {}", output.status);
    }
    Ok(())
}

/// Tolerant parsing of the `end` section of iperf3 UDP JSON output.
///
/// Newer iperf3 versions report the sender and receiver summaries separately in
/// `end.sum_sent` and `end.sum_received`; older versions only emit the ambiguous
/// `end.sum`, disambiguated by its `sender` flag.
pub mod iperf_udp {
    use std::process::Output;

    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct UdpOutput {
        pub end: UdpEnd,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct UdpEnd {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sum: Option<UdpSummary>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sum_sent: Option<UdpSummary>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sum_received: Option<UdpSummary>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct UdpSummary {
        pub bits_per_second: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jitter_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lost_percent: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sender: Option<bool>,
    }

    impl UdpEnd {
        /// The sender-side summary, if the test reported one.
        pub fn sent(&self) -> Option<&UdpSummary> {
            self.sum_sent.as_ref().or_else(|| {
                self.sum
                    .as_ref()
                    .filter(|summary| summary.sender == Some(true))
            })
        }

        /// The receiver-side summary, if the test reported one. This is the side that
        /// carries jitter and loss statistics.
        pub fn received(&self) -> Option<&UdpSummary> {
            self.sum_received.as_ref().or_else(|| {
                self.sum
                    .as_ref()
                    .filter(|summary| summary.sender == Some(false))
            })
        }
    }

    pub fn parse(output: &Output) -> anyhow::Result<UdpOutput> {
        use anyhow::Context as _;
        if !output.status.success() {
            anyhow::bail!(
                "iperf3 failed with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        serde_json::from_slice(&output.stdout)
            .context("failed to deserialize iperf3 UDP JSON output")
    }
}

async fn wait_for_marker_lines<R: AsyncRead + Unpin>(
    lines: &mut Lines<BufReader<R>>,
    marker: &str,
    name: &str,
) -> Result<()> {
    timeout(READY_TIMEOUT, async {
        let mut last_line = String::new();
        while let Some(line) = lines
            .next_line()
            .await
            .context("failed to read process output")?
        {
            if line.contains(marker) {
                return Ok(());
            }
            tracing::info!("{name}: {line}");
            last_line = line;
        }
        bail!("the process exited before reporting readiness; last output: {last_line:?}")
    })
    .await
    .context("timed out waiting for process readiness")?
}

fn drain_remaining<R: AsyncRead + Unpin + Send + 'static>(lines: Lines<BufReader<R>>, name: &str) {
    let name = name.to_owned();
    tokio::spawn(async move {
        let mut lines = lines;
        while let Ok(Some(line)) = lines.next_line().await {
            tracing::info!("{name}: {line}");
        }
    });
}

pub fn scratch_dir_name() -> String {
    format!("/tmp/benchy-{}", run_id())
}

fn run_id() -> String {
    env::var("GITHUB_RUN_ID").unwrap_or_else(|_| std::process::id().to_string())
}

fn env_value(key: &str, default: &str) -> String {
    env::var(key)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

pub fn remote_command(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .map(shell_quote)
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
}

#[cfg(test)]
mod tests {
    use super::{LocalProcess, iperf_udp, remote_command, shell_quote, validate_udp_result};

    #[tokio::test]
    async fn local_readiness_is_detected_on_stderr() {
        let mut process = LocalProcess::spawn(
            "sh",
            &[
                "-c".to_owned(),
                "echo 'Listening on test' >&2; exec sleep 10".to_owned(),
            ],
            Some("Listening on"),
        )
        .await
        .unwrap();
        process.stop().await;
    }

    #[test]
    fn shell_arguments_are_single_quoted() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(
            remote_command("some command", &["an argument".to_owned()]),
            "'some command' 'an argument'"
        );
    }

    #[test]
    fn udp_iperf_output_parses_separate_sender_and_receiver_summaries() {
        let json = serde_json::json!({
            "end": {
                "sum_sent": {
                    "bits_per_second": 900_000_000.0,
                    "jitter_ms": 0.0,
                    "lost_packets": 0,
                    "packets": 7500,
                    "lost_percent": 0.0,
                    "sender": true
                },
                "sum_received": {
                    "bits_per_second": 810_000_000.0,
                    "jitter_ms": 0.007,
                    "lost_packets": 75,
                    "packets": 7425,
                    "lost_percent": 1.0,
                    "sender": false
                }
            }
        });

        let output: iperf_udp::UdpOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.end.sent().unwrap().bits_per_second, 900_000_000.0);
        let received = output.end.received().unwrap();
        assert_eq!(received.bits_per_second, 810_000_000.0);
        assert_eq!(received.lost_percent, Some(1.0));
        assert_eq!(received.jitter_ms, Some(0.007));
    }

    #[test]
    fn udp_iperf_output_parses_legacy_ambiguous_summary() {
        let json = serde_json::json!({
            "end": {
                "sum": {
                    "bits_per_second": 810_000_000.0,
                    "jitter_ms": 0.007,
                    "lost_percent": 1.0,
                    "sender": false
                }
            }
        });

        let output: iperf_udp::UdpOutput = serde_json::from_value(json).unwrap();
        assert!(output.end.sent().is_none());
        let received = output.end.received().unwrap();
        assert_eq!(received.bits_per_second, 810_000_000.0);
        assert_eq!(received.lost_percent, Some(1.0));
    }

    #[test]
    fn udp_iperf_output_prefers_explicit_summaries() {
        let output: iperf_udp::UdpOutput = serde_json::from_value(serde_json::json!({
            "end": {
                "sum": { "bits_per_second": 1.0, "sender": false },
                "sum_sent": { "bits_per_second": 2.0, "sender": true },
                "sum_received": { "bits_per_second": 3.0, "sender": false }
            }
        }))
        .unwrap();
        assert_eq!(output.end.sent().unwrap().bits_per_second, 2.0);
        assert_eq!(output.end.received().unwrap().bits_per_second, 3.0);
    }

    #[test]
    fn udp_iperf_output_requires_receiver_summary() {
        let output: iperf_udp::UdpOutput = serde_json::from_value(serde_json::json!({
            "end": { "sum": { "bits_per_second": 1.0 } }
        }))
        .unwrap();
        assert!(validate_udp_result(output).is_err());
    }
}
