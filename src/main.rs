use std::path::PathBuf;

mod aes;

fn command_line_interface() -> clap::Command {
    clap::Command::new(env!("CARGO_BIN_NAME"))
        .about("An utility to encrypt and decrypt files using AES")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            clap::Command::new("encrypt-file")
                .about("Encrypt file using AES in ECB mode")
                .arg(
                    clap::Arg::new("filepath")
                        .help("path to file to encrypt")
                        .value_parser(clap::value_parser!(PathBuf))
                        .required(true),
                )
                .arg(
                    clap::Arg::new("key")
                        .help("secret key")
                        .value_parser(clap::value_parser!(String))
                        .required(true),
                )
                .arg(
                    clap::Arg::new("output")
                        .help("path to encrypted file")
                        .value_parser(clap::value_parser!(PathBuf))
                        .required(true),
                )
                .arg_required_else_help(true),
        )
        .subcommand(
            clap::Command::new("decrypt-file")
                .about("Decrypt file using AES in ECB mode")
                .arg(
                    clap::Arg::new("filepath")
                        .help("path to file to decrypt")
                        .value_parser(clap::value_parser!(PathBuf))
                        .required(true),
                )
                .arg(
                    clap::Arg::new("key")
                        .help("secret key")
                        .value_parser(clap::value_parser!(String))
                        .required(true),
                )
                .arg(
                    clap::Arg::new("output")
                        .help("path to decrypted file")
                        .value_parser(clap::value_parser!(PathBuf))
                        .required(true),
                )
                .arg_required_else_help(true),
        )
}

fn main() {
    let matches = command_line_interface().get_matches();

    match matches.subcommand() {
        Some(("encrypt-file", sub_matches)) => {
            let filepath = sub_matches.get_one::<PathBuf>("filepath");
            let key = sub_matches.get_one::<String>("key");
            let output = sub_matches.get_one::<PathBuf>("output");
        }
        Some(("decrypt-file", sub_matches)) => {
            let filepath = sub_matches.get_one::<PathBuf>("filepath");
            let key = sub_matches.get_one::<String>("key");
            let output = sub_matches.get_one::<PathBuf>("output");
        }
        _ => unreachable!(),
    }
}
