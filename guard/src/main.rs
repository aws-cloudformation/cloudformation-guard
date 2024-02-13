use std::fs::File;
mod commands;
mod rules;
mod utils;

use crate::commands::{CfnGuard, Commands, Executable};
use crate::utils::reader::{ReadBuffer, Reader};
use crate::utils::writer::WriteBuffer::Stderr;
use crate::utils::writer::{WriteBuffer::File as WBFile, WriteBuffer::Stdout, Writer};
use clap::Parser;
use rules::errors::Error;
use std::process::exit;

fn main() -> Result<(), Error> {
    let args = CfnGuard::parse();

    let mut writer = match &args.command {
        Commands::ParseTree(cmd) => match &cmd.output {
            Some(path) => Writer::new(WBFile(File::create(path)?), Stderr(std::io::stderr())),
            None => Writer::new(Stdout(std::io::stdout()), Stderr(std::io::stderr())),
        },
        Commands::Rulegen(cmd) => match &cmd.output {
            Some(path) => Writer::new(WBFile(File::create(path)?), Stderr(std::io::stderr())),
            None => Writer::new(Stdout(std::io::stdout()), Stderr(std::io::stderr())),
        },
        _ => Writer::new(Stdout(std::io::stdout()), Stderr(std::io::stderr())),
    };
    let mut reader = Reader::new(ReadBuffer::Stdin(std::io::stdin()));

    let exit_code = match args.command {
        Commands::Validate(cmd) => cmd.execute(&mut writer, &mut reader),
        Commands::Test(cmd) => cmd.execute(&mut writer, &mut reader),
        Commands::ParseTree(cmd) => cmd.execute(&mut writer, &mut reader),
        Commands::Rulegen(cmd) => cmd.execute(&mut writer, &mut reader),
        Commands::Completions(cmd) => cmd.execute(),
    };

    match exit_code {
        Ok(code) => exit(code),
        Err(e) => {
            writer
                .write_err(format!("Error occurred {e}"))
                .expect("failed to write to stderr");

            exit(-1)
        }
    }
}
