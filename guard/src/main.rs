use std::fs::File;
mod commands;
mod rules;
mod utils;

use crate::commands::{CfnGuard, Commands};
use crate::utils::reader::{ReadBuffer, Reader};
use crate::utils::writer::{WriteBuffer::File as WBFile, WriteBuffer::Stdout, Writer};
use clap::Parser;
use rules::errors::Error;
use std::io::Write;
use std::process::exit;

/// A combination of arguments the command cannot honour.
///
/// clap answers a usage error with 2, and an `Error::IllegalArguments` raised after parsing is the
/// same class of mistake reached by a different layer: `validate -P -r x` is caught by clap and
/// `validate -z -o json -S fail` is caught by `validate_construct`, and both are the caller's to fix.
/// They exited 2 and 255 respectively, so a build step could not treat "you passed the wrong flags"
/// as one outcome, and 255 -- which `guard/README.md` gives to cfn-guard itself failing -- said the
/// tool was broken.
const USAGE_ERROR: i32 = 2;

/// The code for cfn-guard itself failing to reach a verdict, per the table in `guard/README.md`.
/// `exit` takes it as -1, which the shell reports as 255.
const INTERNAL_FAILURE: i32 = -1;

fn main() {
    let args = CfnGuard::parse();

    let mut writer = match &args.command {
        Commands::ParseTree(cmd) => match &cmd.output {
            Some(path) => {
                Writer::new(WBFile(create_output_file(path))).expect("Failed to create writer.")
            }
            None => Writer::new(Stdout(std::io::stdout())).expect("Failed to create writer."),
        },
        Commands::Rulegen(cmd) => match &cmd.output {
            Some(path) => {
                Writer::new(WBFile(create_output_file(path))).expect("Failed to create writer.")
            }
            None => Writer::new(Stdout(std::io::stdout())).expect("Failed to create writer."),
        },
        _ => Writer::new(Stdout(std::io::stdout())).expect("Failed to create writer."),
    };

    let mut reader = Reader::new(ReadBuffer::Stdin(std::io::stdin()));

    match args.execute(&mut writer, &mut reader) {
        Ok(code) => exit(code),
        Err(Error::IllegalArguments(message)) => {
            writer
                .write_err(format!("Error occurred {message}"))
                .expect("failed to write to stderr");

            exit(USAGE_ERROR)
        }
        Err(e) => {
            writer
                .write_err(format!("Error occurred {e}"))
                .expect("failed to write to stderr");

            exit(INTERNAL_FAILURE)
        }
    }
}

/// Opens the file `--output` names, or reports why it could not be opened and exits.
///
/// This runs before `execute`, so the failure never reached the `Err` arm above and never got its
/// `Error occurred` prefix. `main` returned `Err` instead, and Rust's default `Termination` printed
/// the `Debug` form of the error and exited **1** --
/// `Error: IoError(Os { code: 2, kind: NotFound, message: "No such file or directory" })`. Three
/// things were wrong with that: 1 is `TEST_ERROR_STATUS_CODE`, so an unwritable path collided with a
/// `test` verdict; a struct dump is not a sentence; and it named neither the path nor the flag.
///
/// The code is `INTERNAL_FAILURE`, which is what every other unusable path in the tool already
/// answers -- a missing `--rules` file exits it from all three subcommands, and `guard/README.md`
/// says 255 "also covers a path that does not exist".
fn create_output_file(path: &str) -> File {
    match File::create(path) {
        Ok(file) => file,
        Err(e) => {
            let mut stderr = std::io::stderr();
            writeln!(
                stderr,
                "Error occurred Unable to open the --output file `{path}`: {e}"
            )
            .expect("failed to write to stderr");

            exit(INTERNAL_FAILURE)
        }
    }
}
