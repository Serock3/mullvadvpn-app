use std::{
    env,
    fs::{self, OpenOptions},
    io::Write as _,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::fs::OpenOptionsExt as _,
    path::PathBuf,
    process::Stdio,
    time::{SystemTime, UNIX_EPOCH},
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
use tokio::{io::AsyncWriteExt, process::Command};

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
    let keys = WireguardKeys::generate().await?;
    let mut tunnel = setup_wireguard(config, &keys).await?;
    let result = async {
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

    tunnel.stop().await;
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

struct WireguardTunnel {
    peer: String,
    interface: String,
    alice_created: bool,
    bob_created: bool,
}

impl WireguardTunnel {
    async fn stop(&mut self) {
        if self.bob_created {
            let _ = sudo_remote(&self.peer, &["ip", "link", "del", &self.interface]).await;
            self.bob_created = false;
        }
        if self.alice_created {
            let _ = sudo(&["ip", "link", "del", &self.interface]).await;
            self.alice_created = false;
        }
    }
}

struct PrivateConfigFile(PathBuf);

impl PrivateConfigFile {
    fn new(contents: &str) -> Result<Self> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path =
            env::temp_dir().join(format!("benchy-wg-{}-{timestamp}.conf", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .context("failed to create private WireGuard config")?;
        let config = Self(path);
        file.write_all(contents.as_bytes())
            .context("failed to write private WireGuard config")?;
        Ok(config)
    }

    fn path(&self) -> Result<&str> {
        self.0
            .to_str()
            .context("WireGuard config path is not valid UTF-8")
    }
}

impl Drop for PrivateConfigFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

async fn setup_wireguard(config: &Config, keys: &WireguardKeys) -> Result<WireguardTunnel> {
    let mut tunnel = WireguardTunnel {
        peer: config.peer.clone(),
        interface: config.interface.clone(),
        alice_created: false,
        bob_created: false,
    };
    if let Err(error) = configure_wireguard(config, keys, &mut tunnel).await {
        tunnel.stop().await;
        return Err(error);
    }
    Ok(tunnel)
}

async fn configure_wireguard(
    config: &Config,
    keys: &WireguardKeys,
    tunnel: &mut WireguardTunnel,
) -> Result<()> {
    let interface = config.interface.as_str();
    sudo(&["ip", "link", "add", interface, "type", "wireguard"]).await?;
    tunnel.alice_created = true;
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

    let alice_conf = PrivateConfigFile::new(&keys.alice_config(config))?;
    sudo(&["wg", "setconf", interface, alice_conf.path()?]).await?;
    drop(alice_conf);

    let scratch = scratch_dir_name();
    let remote_conf = format!("{scratch}/wg-bob.conf");
    remote_write_file(&config.peer, &remote_conf, &keys.bob_config(config)).await?;

    sudo_remote(
        &config.peer,
        &["ip", "link", "add", interface, "type", "wireguard"],
    )
    .await?;
    tunnel.bob_created = true;
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

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf};

    use super::PrivateConfigFile;

    #[test]
    fn private_config_is_restricted_and_removed() {
        let path: PathBuf;
        {
            let config = PrivateConfigFile::new("private key").unwrap();
            path = PathBuf::from(config.path().unwrap());
            assert_eq!(fs::read_to_string(&path).unwrap(), "private key");
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(!path.exists());
    }
}
