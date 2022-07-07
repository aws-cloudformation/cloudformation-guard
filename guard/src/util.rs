use config::Config;
use regex::Regex;


/// Function to read config from TOML
fn read_config(file_name:String) -> HashMap<String, String> {
    let settings = Config::builder()
        .add_source(config::File::with_name(file_name))
        .build()
        .unwrap();

    // put details into a hashmap and create a new instance
    let args = settings.try_deserialize::<HashMap<String, String>>().unwrap();
    return args;
}

/// Function to check version format
fn validate_version(version_name:String) -> bool {
    let mut output = false
    let re = Regex::new(r"^(\d+\.)?(\d+\.)?(\*|\d+)$").unwrap();
    let caps = re.captures(version_name).unwrap();
    if &caps[0] {
        output = true;
    }
    return output
}