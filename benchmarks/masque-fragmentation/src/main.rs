use benchy_runner::BenchmarkDefinition;
use masque_common::run_udp_benchmark;

const DEFINITION: BenchmarkDefinition = BenchmarkDefinition {
    repository: "mullvadvpn-app",
    name: "masque-fragmentation",
    description: "MASQUE proxy throughput with fragmented datagrams measured with UDP iperf3",
};
const DATAGRAM_LENGTH: u16 = 2200;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    masque_common::init_logging();
    run_udp_benchmark(DEFINITION, DATAGRAM_LENGTH).await
}
