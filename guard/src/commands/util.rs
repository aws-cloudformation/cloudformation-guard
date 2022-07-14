use config::Config;
use regex::Regex;
use crate::commands::SEMANTIC_VERSION_NAMING;
use std::collections::HashMap;


/// Function to read config from TOML
pub fn read_config(file_name:String) -> HashMap<String, String> {
    let settings = Config::builder()
        .add_source(config::File::with_name(file_name))
        .build()
        .unwrap();

    // put details into a hashmap and create a new instance
    let args = settings.try_deserialize::<HashMap<String, String>>().unwrap();
    return args;
}

/// Function to check version format
pub fn validate_version(version_name:String) -> bool {
    let mut output;
    let re = Regex::new(SEMANTIC_VERSION_NAMING).unwrap();
    output = re.is_match(&version_name);
    return output
}