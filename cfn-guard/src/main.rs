// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::process;
#[macro_use]
extern crate log;
extern crate lazy_static;
extern crate simple_logger;
use cfn_guard_rulegen;
use clap::{crate_version, App, AppSettings, Arg, SubCommand};
use log::Level;

fn main() {
    let matches = App::new("CloudFormation Guard")
        .setting(AppSettings::ArgRequiredElseHelp)
        .version(crate_version!())
        .subcommand(
            SubCommand::with_name("check")
                .about("Check CloudFormation templates against rules")
                .arg(
                    Arg::with_name("template")
                        .short("t")
                        .long("template")
                        .value_name("TEMPLATE_FILE")
                        .help("CloudFormation Template")
                        .required(true),
                )
                .arg(
                    Arg::with_name("rule_set")
                        .short("r")
                        .long("rule_set")
                        .value_name("RULE_SET_FILE")
                        .help("Rules to check the template against")
                        .required(true),
                )
                .arg(
                    Arg::with_name("warn-only")
                        .short("w")
                        .long("warn_only")
                        .help(
                        "Show results but return an exit code of 0 regardless of rule violations",
                    ),
                )
                .arg(
                    Arg::with_name("strict-checks")
                        .short("s")
                        .long("strict-checks")
                        .help("Fail resources if they're missing the property that a rule checks"),
                )
                .arg(
                    Arg::with_name("v")
                        .short("v")
                        .multiple(true)
                        .help("Sets the level of verbosity - add v's to increase output"),
                ),
        )
        .subcommand(
            SubCommand::with_name("rulegen")
                .about("Autogenerate rules from an existing CloudFormation template")
                .arg(Arg::with_name("TEMPLATE").index(1).required(true))
                .arg(
                    Arg::with_name("v")
                        .short("v")
                        .multiple(true)
                        .help("Sets the level of verbosity - add v's to increase output"),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("rulegen") {
        let log_level = match matches.occurrences_of("v") {
            0 => Level::Error,
            1 => Level::Info,
            2 => Level::Debug,
            _ => Level::Trace,
        };

        simple_logger::init_with_level(log_level).unwrap();

        debug!("Parameters are {:#?}", matches);
        let template_file = matches.value_of("TEMPLATE").unwrap();
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
    } else {
        if let Some(matches) = matches.subcommand_matches("check") {
            let log_level = match matches.occurrences_of("v") {
                0 => Level::Error,
                1 => Level::Info,
                2 => Level::Debug,
                _ => Level::Trace,
            };

            simple_logger::init_with_level(log_level).unwrap();

            debug!("Parameters are {:#?}", matches);
            let template_file = matches.value_of("template").unwrap();
            let rule_set_file = matches.value_of("rule_set").unwrap();

            info!(
                "CloudFormation Guard is checking the template '{}' against the rules in '{}'",
                &template_file, &rule_set_file
            );

            let (result, exit_code) = cfn_guard::run(
                template_file,
                rule_set_file,
                matches.is_present("strict-checks"),
            )
            .unwrap_or_else(|err| {
                println!("Problem checking template: {}", err);
                process::exit(1);
            });

            if !result.is_empty() {
                for res in result.iter() {
                    println!("{}", res);
                }
                println!("Number of failures: {}", result.len());
                if matches.is_present("warn-only") {
                    process::exit(0);
                } else {
                    process::exit(exit_code as i32);
                }
            } else {
                info!("All CloudFormation resources passed");
            }
        }
    }
}
