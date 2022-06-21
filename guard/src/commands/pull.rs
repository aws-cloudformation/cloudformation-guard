use std::convert::TryFrom;
use std::fs::File;
use std::path::PathBuf;

use clap::{App, Arg, ArgMatches, ArgGroup};


use crate::command::Command;
use crate::commands::{URL};
// use crate::commands::files::{alpabetical, last_modified, regular_ordering, iterate_over, get_files_with_filter, read_file_content};
// use crate::rules::{Evaluate, Result, Status, RecordType, NamedStatus};
// use crate::rules::errors::{Error, ErrorKind};
// use crate::rules::evaluate::RootScope;
// use crate::rules::exprs::RulesFile;
//
// use std::collections::{HashMap, BTreeMap};
// use crate::rules::path_value::PathAwareValue;
// use crate::commands::tracker::{StackTracker};
// use serde::{Serialize, Deserialize};
// use itertools::Itertools;
// use crate::rules::eval::eval_rules_file;
// use crate::rules::Status::SKIP;
// use walkdir::DirEntry;

use config::Config;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Pull {}

impl Pull {
    pub(crate) fn new() -> Self {
        Pull{}
    }
}

impl Command for Pull {
    fn name(&self) -> &'static str {
        PULL
    }


    fn command(&self) -> App<'static, 'static> {
        App::new(PULL)
            .about(r#"Pull from GitHub
"#)
            .arg(Arg::with_name(URL)
                .long(URL.0)
                .short(URL.1)
                .takes_value(true)
                .help("Provide the url for pulling"))
    }

    fn execute(&self, app: &ArgMatches<'_>) -> Result<i32> {
        let mut exit_code = 0;
        let settings = Config::builder()
            .add_source(config::File::with_name("src/setting"))
            .build()
            .unwrap();

        let args = settings.try_deserialize::<HashMap<String, String>>().unwrap();
        let owner = args.get("owner").unwrap();
        let repo_name = args.get("repo_name").unwrap();
        let file_name = args.get("file_name").unwrap();
        let access_token = args.get("api_key").unwrap();
        let sign = args.get("sign").unwrap();
        let version_needed = args.get("version_needed").unwrap();

        Ok(exit_code)
    }
}
