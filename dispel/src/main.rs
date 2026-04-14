use clap::Parser;
mod cli;

fn main() {
    let args = cli::Cli::parse();
    match args.run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(3);
        }
    }
}
