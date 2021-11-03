use clap::{App, ArgMatches};

use crate::rules::errors::Error;

pub(crate) trait Command {
    fn name(&self) -> &'static str;
    fn command(&self) -> App<'static, 'static>;
    fn execute(&self, args: &ArgMatches) -> Result<i32, Error>;
}
