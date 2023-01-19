use clap::{App, ArgMatches};

use crate::utils::writer::Writer;
use crate::rules::errors::Error;

pub trait Command {
    fn name(&self) -> &'static str;
    fn command(&self) -> App<'static, 'static>;
    fn execute(&self, args: &ArgMatches, writer: &mut Writer) -> Result<i32, Error>;
}


