use clap::ArgMatches;

use crate::rules::errors::Error;

pub trait Command {
    fn name(&self) -> &'static str;
    fn command(&self) -> clap::Command;
    fn execute(&self, args: &ArgMatches) -> Result<i32, Error>;
}