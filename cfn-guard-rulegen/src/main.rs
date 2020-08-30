// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::process;
#[macro_use]
extern crate log;
extern crate simple_logger;
use clap::{crate_version, App, Arg};
use log::Level;

fn main() {
    let matches = App::new("CloudFormation Guard RuleGen")
        .version(crate_version!())
        .about("Generate cfn-guard rules from a CloudFormation template")
        .arg(Arg::with_name("TEMPLATE").index(1).required(true))
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity - add v's to increase output"),
        )
        .get_matches();

    let log_level = match matches.occurrences_of("v") {
        0 => Level::Error,
        1 => Level::Info,
        2 => Level::Debug,
        3 | _ => Level::Trace,
    };

    simple_logger::init_with_level(log_level).unwrap();

    trace!("Arguments are {:?}", matches);

    let template_file = matches.value_of("TEMPLATE").unwrap();

    info!("Generating rules from {}", &template_file);

    let mut result = cfn_guard_rulegen::run(template_file).unwrap_or_else(|err| {
        println!("Problem generating rules: {}", err);
        process::exit(1);
    });

    if !result.is_empty() {
	result.sort();
        for res in result.iter() {
            println!("{}", res);
        }
    }
    process::exit(0);
}
