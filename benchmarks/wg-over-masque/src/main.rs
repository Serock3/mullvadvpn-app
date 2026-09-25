use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::Stdio,
};

use anyhow::{Context, Result, bail};
use benchy_lib::{Unit, iperf};
use benchy_runner::{
    BenchmarkDefinition, MachineLock, MeasurementDefinition, Recorder, checked_output,
    default_output_path, parse_iperf_output,
};
use masque_common::{
    Config, MasqueProxies, iperf_server, remote_command, remote_write_file, scratch_dir_name,
    wait_for_tunnel, wait_local_tcp,
};
use tokio::{fs, io::AsyncWriteExt, process::Command};

const DEFINITION: BenchmarkDefinition = BenchmarkDefinition {
    repository: "mullvadvpn-app",
    name: "wg-over-masque",
    description: "Kernel WireGuard tunnel over a MASQUE proxy measured with iperf3",
};
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
const UP_IPERF_CPU: MeasurementDefinition = MeasurementDefinition {
    id: "cpu.iperf.up",
    label: "UP iperf CPU",
    unit: Unit::Percent,
};
const DOWN_IPERF_CPU: MeasurementDefinition = MeasurementDefinition {
    id: "cpu.iperf.down",
    label: "DOWN iperf CPU",
    unit: Unit::Percent,
};

const ALICE_TUNNEL_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 1);
const BOB_TUNNEL_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2);
const TUNNEL_SUBNET: &str = "10.0.1.0/24";

#[tokio::main]
async fn main() -> Result<()> {
    masque_common::init_logging();

    let mut recorder = Recorder::new(DEFINITION, default_output_path(DEFINITION.name)).await;
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            recorder.failure(&error).await?;
            return Err(error);
        }
    };
    recorder.parameter("duration_seconds", config.duration);
    recorder.parameter("tunnel_mtu", config.tunnel_mtu);
    recorder.parameter("masque_mtu", config.masque_mtu);
    recorder.parameter("wireguard_port", config.wireguard_port);

    match controller(&config).await {
        Ok(iperf) => {
            recorder.measurement(SENDER_THROUGHPUT, iperf.end.sum_sent.bits_per_second)?;
            recorder.measurement(RECEIVER_THROUGHPUT, iperf.end.sum_received.bits_per_second)?;
            recorder.measurement(
                DOWN_IPERF_CPU,
                iperf.end.cpu_utilization_percent.remote_total,
            )?;
            recorder.measurement(UP_IPERF_CPU, iperf.end.cpu_utilization_percent.host_total)?;
            recorder.success().await
        }
        Err(error) => {
            recorder.failure(&error).await?;
            Err(error)
        }
    }
}

async fn controller(config: &Config) -> Result<iperf::Output> {
    let _machine_lock = MachineLock::acquire("/tmp/benchy.lock")?;

    // The MASQUE client on Bob forwards datagrams to Alice's WireGuard listen port on
    // the server-side loopback.
    let mut proxies = MasqueProxies::start(
        config,
        SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), config.wireguard_port),
    )
    .await?;
    let result = tunnel_run(config).await;
    proxies.stop().await;
    result
}

async fn tunnel_run(config: &Config) -> Result<iperf::Output> {
    let result = async {
        let keys = WireguardKeys::generate().await?;
        setup_wireguard(config, &keys).await?;

        let mut iperf = iperf_server(IpAddr::from(ALICE_TUNNEL_ADDRESS), config.iperf_port).await?;
        let result = async {
            wait_for_tunnel(&config.peer, ALICE_TUNNEL_ADDRESS).await?;
            wait_local_tcp(SocketAddr::new(
                IpAddr::from(ALICE_TUNNEL_ADDRESS),
                config.iperf_port,
            ))
            .await?;

            let iperf_command = remote_command(
                "iperf3",
                &[
                    "--json".to_owned(),
                    "--client".to_owned(),
                    ALICE_TUNNEL_ADDRESS.to_string(),
                    "--port".to_owned(),
                    config.iperf_port.to_string(),
                    "--time".to_owned(),
                    config.duration.to_string(),
                ],
            );
            let output = checked_output("ssh", [&config.peer, &iperf_command]).await?;
            parse_iperf_output(output).await
        }
        .await;
        iperf.stop().await;
        result
    }
    .await;

    teardown_wireguard(config).await;
    result
}

struct WireguardKeys {
    alice_private: String,
    alice_public: String,
    bob_private: String,
    bob_public: String,
    preshared_key: String,
}

impl WireguardKeys {
    async fn generate() -> Result<Self> {
        let alice_private = wg_key(&["genkey"], "").await?;
        let alice_public = wg_key(&["pubkey"], &alice_private).await?;
        let bob_private = wg_key(&["genkey"], "").await?;
        let bob_public = wg_key(&["pubkey"], &bob_private).await?;
        let preshared_key = wg_key(&["genpsk"], "").await?;
        Ok(Self {
            alice_private,
            alice_public,
            bob_private,
            bob_public,
            preshared_key,
        })
    }

    fn peer_config(&self, public_key: &str) -> String {
        format!(
            "[Peer]\nPublicKey = {public_key}\nPresharedKey = {}\nAllowedIPs = {TUNNEL_SUBNET}\n",
            self.preshared_key
        )
    }

    /// Alice does not set an endpoint; she learns it from Bob's handshake.
    fn alice_config(&self, config: &Config) -> String {
        format!(
            "[Interface]\nListenPort = {}\nPrivateKey = {}\n\n{}",
            config.wireguard_port,
            self.alice_private,
            self.peer_config(&self.bob_public)
        )
    }

    fn bob_config(&self, config: &Config) -> String {
        format!(
            "[Interface]\nListenPort = {}\nPrivateKey = {}\n\n{}Endpoint = 127.0.0.1:{}\n",
            config.wireguard_port,
            self.bob_private,
            self.peer_config(&self.alice_public),
            config.masque_client_port
        )
    }
}

async fn wg_key(args: &[&str], stdin_data: &str) -> Result<String> {
    let mut child = Command::new("wg")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to run wg {}", args.join(" ")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(stdin_data.as_bytes())
            .await
            .with_context(|| format!("failed to write to wg {}", args.join(" ")))?;
    }
    let output = child
        .wait_with_output()
        .await
        .with_context(|| format!("failed to run wg {}", args.join(" ")))?;
    if !output.status.success() {
        bail!("wg {} failed with {}", args.join(" "), output.status);
    }
    String::from_utf8(output.stdout)
        .with_context(|| format!("wg {} produced non-UTF-8 output", args.join(" ")))
        .map(|key| key.trim().to_owned())
}

async fn setup_wireguard(config: &Config, keys: &WireguardKeys) -> Result<()> {
    let interface = config.interface.as_str();
    sudo(&["ip", "link", "add", interface, "type", "wireguard"]).await?;
    sudo(&[
        "ip",
        "address",
        "replace",
        &tunnel_address(ALICE_TUNNEL_ADDRESS),
        "dev",
        interface,
    ])
    .await?;
    sudo(&[
        "ip",
        "link",
        "set",
        "dev",
        interface,
        "mtu",
        &config.tunnel_mtu.to_string(),
        "up",
    ])
    .await?;

    let scratch = scratch_dir_name();
    fs::create_dir_all(&scratch).await?;
    let alice_conf = format!("{scratch}/wg-alice.conf");
    fs::write(&alice_conf, keys.alice_config(config)).await?;
    sudo(&["wg", "setconf", interface, &alice_conf]).await?;

    let remote_conf = format!("{scratch}/wg-bob.conf");
    remote_write_file(&config.peer, &remote_conf, &keys.bob_config(config)).await?;

    sudo_remote(
        &config.peer,
        &["ip", "link", "add", interface, "type", "wireguard"],
    )
    .await?;
    sudo_remote(
        &config.peer,
        &[
            "ip",
            "address",
            "replace",
            &tunnel_address(BOB_TUNNEL_ADDRESS),
            "dev",
            interface,
        ],
    )
    .await?;
    sudo_remote(
        &config.peer,
        &[
            "ip",
            "link",
            "set",
            "dev",
            interface,
            "mtu",
            &config.tunnel_mtu.to_string(),
            "up",
        ],
    )
    .await?;
    sudo_remote(&config.peer, &["wg", "setconf", interface, &remote_conf]).await?;
    Ok(())
}

async fn teardown_wireguard(config: &Config) {
    let interface = config.interface.as_str();
    let _ = sudo(&["ip", "link", "del", interface]).await;
    let _ = sudo_remote(&config.peer, &["ip", "link", "del", interface]).await;
}

fn tunnel_address(address: Ipv4Addr) -> String {
    format!("{address}/24")
}

async fn sudo(args: &[&str]) -> Result<()> {
    let mut sudo_args = vec!["-n"];
    sudo_args.extend(args);
    checked_output("sudo", sudo_args)
        .await
        .with_context(|| format!("failed to run sudo {}", args.join(" ")))?;
    Ok(())
}

async fn sudo_remote(peer: &str, args: &[&str]) -> Result<()> {
    let mut sudo_args = vec!["-n".to_owned()];
    sudo_args.extend(args.iter().map(|arg| (*arg).to_owned()));
    let command = remote_command("sudo", &sudo_args);
    checked_output("ssh", [peer, &command])
        .await
        .with_context(|| format!("failed to run sudo {} on the peer", args.join(" ")))?;
    Ok(())
}
