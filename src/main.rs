mod config;
mod proxy;
mod gen;
mod check;

use argh::FromArgs;

#[cfg(feature = "mimallocator")]
#[global_allocator]
static GLOBAL: mimallocator::Mimalloc = mimallocator::Mimalloc;


/// No SNI tools
#[derive(FromArgs)]
struct Options {
    #[argh(subcommand)]
    subcmd: SubCommands,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum SubCommands {
    Proxy(proxy::Options),
    Check(check::Options),
    Gen(gen::Options),
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let options: Options = argh::from_env();

    match options.subcmd {
        SubCommands::Proxy(cmd) => cmd.exec().await?,
        SubCommands::Check(cmd) => cmd.exec().await?,
        SubCommands::Gen(cmd) => cmd.exec()?
    }

    Ok(())
}
