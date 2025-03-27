use crate::aes::{Key, State};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;

mod aes;

fn main() {
    let matches = command_line_interface().get_matches();

    match matches.subcommand() {
        Some(("encrypt-file", sub_matches)) => {
            let filepath = sub_matches.get_one::<PathBuf>("filepath").unwrap();
            let keyfile = sub_matches.get_one::<PathBuf>("keyfile").unwrap();
            let output = sub_matches.get_one::<PathBuf>("output").unwrap();

            let file_to_encrypt = File::open(filepath).unwrap();
            let mut file_to_encrypt_reader = BufReader::new(file_to_encrypt);
            let mut output_file = File::create(output).unwrap();

            let mut buffer = [0u8; 16];
            while let Ok(num_of_bytes_read) = file_to_encrypt_reader.read(&mut buffer) {
                if num_of_bytes_read == 0 {
                    break;
                }

                if num_of_bytes_read < 16 {
                    buffer[num_of_bytes_read] = 0x80;
                }

                let mut key_buf = vec![];
                let key = File::open(keyfile).unwrap();
                let mut key_file_reader = BufReader::new(key);
                key_file_reader.read_to_end(&mut key_buf).unwrap();

                match key_buf.len() {
                    16 => {
                        let key = Key::from([
                            key_buf[0],
                            key_buf[1],
                            key_buf[2],
                            key_buf[3],
                            key_buf[4],
                            key_buf[5],
                            key_buf[6],
                            key_buf[7],
                            key_buf[8],
                            key_buf[9],
                            key_buf[10],
                            key_buf[11],
                            key_buf[12],
                            key_buf[13],
                            key_buf[14],
                            key_buf[15],
                        ]);

                        let mut block = State::new(buffer);
                        block.encrypt_128(key);
                        let _ = output_file.write(block.as_vec().as_slice());
                    }
                    24 => {
                        let key = Key::from([
                            key_buf[0],
                            key_buf[1],
                            key_buf[2],
                            key_buf[3],
                            key_buf[4],
                            key_buf[5],
                            key_buf[6],
                            key_buf[7],
                            key_buf[8],
                            key_buf[9],
                            key_buf[10],
                            key_buf[11],
                            key_buf[12],
                            key_buf[13],
                            key_buf[14],
                            key_buf[15],
                            key_buf[16],
                            key_buf[17],
                            key_buf[18],
                            key_buf[19],
                            key_buf[20],
                            key_buf[21],
                            key_buf[22],
                            key_buf[23],
                        ]);

                        let mut block = State::new(buffer);
                        block.encrypt_192(key);
                        let _ = output_file.write(block.as_vec().as_slice());
                    }
                    32 => {
                        let key = Key::from([
                            key_buf[0],
                            key_buf[1],
                            key_buf[2],
                            key_buf[3],
                            key_buf[4],
                            key_buf[5],
                            key_buf[6],
                            key_buf[7],
                            key_buf[8],
                            key_buf[9],
                            key_buf[10],
                            key_buf[11],
                            key_buf[12],
                            key_buf[13],
                            key_buf[14],
                            key_buf[15],
                            key_buf[16],
                            key_buf[17],
                            key_buf[18],
                            key_buf[19],
                            key_buf[20],
                            key_buf[21],
                            key_buf[22],
                            key_buf[23],
                            key_buf[24],
                            key_buf[25],
                            key_buf[26],
                            key_buf[27],
                            key_buf[28],
                            key_buf[29],
                            key_buf[30],
                            key_buf[31],
                        ]);

                        let mut block = State::new(buffer);
                        block.encrypt_256(key);
                        let _ = output_file.write(block.as_vec().as_slice());
                    }
                    _ => {
                        panic!("Key length must be 16, 24 or 32 bytes");
                    }
                }
                buffer = [0u8; 16];
            }
        }
        Some(("decrypt-file", sub_matches)) => {
            let filepath = sub_matches.get_one::<PathBuf>("filepath").unwrap();
            let keyfile = sub_matches.get_one::<PathBuf>("keyfile").unwrap();
            let output = sub_matches.get_one::<PathBuf>("output").unwrap();

            let file_to_decrypt = File::open(filepath).unwrap();
            let mut file_to_decrypt_reader = BufReader::new(file_to_decrypt);
            let mut output_file = File::create(output).unwrap();

            let mut buffer = [0u8; 16];
            while let Ok(num_of_bytes_read) = file_to_decrypt_reader.read(&mut buffer) {
                if num_of_bytes_read == 0 {
                    break;
                }

                if num_of_bytes_read % 16 != 0 {
                    panic!("Ciphertext length must be multiple of 16");
                }

                let mut key_buf = vec![];
                let key = File::open(keyfile).unwrap();
                let mut key_file_reader = BufReader::new(key);
                key_file_reader.read_to_end(&mut key_buf).unwrap();

                match key_buf.len() {
                    16 => {
                        let key = Key::from([
                            key_buf[0],
                            key_buf[1],
                            key_buf[2],
                            key_buf[3],
                            key_buf[4],
                            key_buf[5],
                            key_buf[6],
                            key_buf[7],
                            key_buf[8],
                            key_buf[9],
                            key_buf[10],
                            key_buf[11],
                            key_buf[12],
                            key_buf[13],
                            key_buf[14],
                            key_buf[15],
                        ]);

                        let mut block = State::new(buffer);
                        block.decrypt_128(key);
                        let out = block.as_vec();
                        let _ = output_file.write(out.as_slice());
                    }
                    24 => {
                        let key = Key::from([
                            key_buf[0],
                            key_buf[1],
                            key_buf[2],
                            key_buf[3],
                            key_buf[4],
                            key_buf[5],
                            key_buf[6],
                            key_buf[7],
                            key_buf[8],
                            key_buf[9],
                            key_buf[10],
                            key_buf[11],
                            key_buf[12],
                            key_buf[13],
                            key_buf[14],
                            key_buf[15],
                            key_buf[16],
                            key_buf[17],
                            key_buf[18],
                            key_buf[19],
                            key_buf[20],
                            key_buf[21],
                            key_buf[22],
                            key_buf[23],
                        ]);

                        let mut block = State::new(buffer);
                        block.decrypt_192(key);
                        let _ = output_file.write(block.as_vec().as_slice());
                    }
                    32 => {
                        let key = Key::from([
                            key_buf[0],
                            key_buf[1],
                            key_buf[2],
                            key_buf[3],
                            key_buf[4],
                            key_buf[5],
                            key_buf[6],
                            key_buf[7],
                            key_buf[8],
                            key_buf[9],
                            key_buf[10],
                            key_buf[11],
                            key_buf[12],
                            key_buf[13],
                            key_buf[14],
                            key_buf[15],
                            key_buf[16],
                            key_buf[17],
                            key_buf[18],
                            key_buf[19],
                            key_buf[20],
                            key_buf[21],
                            key_buf[22],
                            key_buf[23],
                            key_buf[24],
                            key_buf[25],
                            key_buf[26],
                            key_buf[27],
                            key_buf[28],
                            key_buf[29],
                            key_buf[30],
                            key_buf[31],
                        ]);

                        let mut block = State::new(buffer);
                        block.decrypt_256(key);
                        let _ = output_file.write(block.as_vec().as_slice());
                    }
                    _ => {
                        panic!("Key length must be 16, 24 or 32 bytes");
                    }
                }
            }
        }
        _ => unreachable!(),
    }
}

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
                    clap::Arg::new("keyfile")
                        .help("path to file with secret key")
                        .value_parser(clap::value_parser!(PathBuf))
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
                    clap::Arg::new("keyfile")
                        .help("path to file with secret key")
                        .value_parser(clap::value_parser!(PathBuf))
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
