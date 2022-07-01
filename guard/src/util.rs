use config::Config;


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