use clap::Parser;

use crate::config::DEFAULT_PORT;

#[derive(Debug, Clone, Parser, PartialEq, Eq)]
#[command(name = "securesshd")]
pub struct Cli {
    #[arg(long, default_value_t = DEFAULT_PORT)]
    pub port: u16,

    /// Run in the foreground instead of daemonizing.
    #[arg(long)]
    pub foreground: bool,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    #[test]
    fn defaults_port_to_50000() {
        let cli = Cli::parse_from(["securesshd"]);

        assert_eq!(cli.port, 50000);
    }

    #[test]
    fn parses_an_explicit_port() {
        let cli = Cli::parse_from(["securesshd", "--port", "60000"]);

        assert_eq!(cli.port, 60000);
    }

    #[test]
    fn rejects_non_numeric_port_values() {
        let result = Cli::try_parse_from(["securesshd", "--port", "not-a-port"]);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_out_of_range_port_values() {
        let result = Cli::try_parse_from(["securesshd", "--port", "70000"]);

        assert!(result.is_err());
    }
}
