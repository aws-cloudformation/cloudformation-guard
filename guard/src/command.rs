use clap::{App, ArgMatches};

use crate::commands::wrapper::Wrapper;
use crate::rules::errors::Error;

pub trait Command {
    fn name(&self) -> &'static str;
    fn command(&self) -> App<'static, 'static>;
    fn execute(&self, args: &ArgMatches, writer: &mut Wrapper) -> Result<i32, Error>;
}


