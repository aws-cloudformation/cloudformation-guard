use clap::{App, ArgMatches};

use crate::rules::errors::Error;
use crate::utils::writer::Writer;

pub trait Command {
    fn name(&self) -> &'static str;
    fn command(&self) -> App<'static>;
    fn execute(&self, args: &ArgMatches, writer: &mut Writer) -> Result<i32, Error>;
}
