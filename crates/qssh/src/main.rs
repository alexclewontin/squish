use anyhow::Result;
use clap::Parser;
use qssh::config::ClientConfig;
use qssh::connection;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "qssh", about = "QSSH client")]
pub struct Cli {
    /// Target as [user@]host[:port]
    pub target: String,

    /// Remote port (overrides the port in the target)
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Username (overrides the user in the target)
    #[arg(short = 'l', long)]
    pub user: Option<String>,

    /// Identity (private key) file
    #[arg(short, long)]
    pub identity: Option<String>,

    /// Local port forward: [bind_addr:]local_port:host:remote_port
    #[arg(short = 'L', value_name = "SPEC")]
    pub local_forward: Vec<String>,

    /// Remote port forward: [bind_addr:]remote_port:host:local_port
    #[arg(short = 'R', value_name = "SPEC")]
    pub remote_forward: Vec<String>,

    /// No shell: only set up port forwards and exit on Ctrl-C
    #[arg(short = 'N')]
    pub no_shell: bool,

    /// Command to execute (if omitted, starts a shell)
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config = ClientConfig::resolve(
        &cli.target,
        cli.port,
        cli.user.as_deref(),
        cli.identity.as_deref(),
        &cli.command,
        &cli.local_forward,
        &cli.remote_forward,
        cli.no_shell,
    )?;

    connection::connect(config).await
}
