use config::Config;
use semver::{BuildMetadata, Prerelease, Version, VersionReq};

/// This is a class for getting file from GitHub
pub struct GitHubSource {
    pub user: String,
    pub repo: String,
    pub file_name: String,
    pub access_token: String,
    pub version_needed: String
}


/// Constructor
impl GitHubSource {
    pub fn new(user: String, repo: String, file_name: String, access_token:String, version_needed: String) -> Self {
        GitHubSource {
            user,
            repo,
            file_name,
            access_token,
            version_needed
        }
    }

    /// Function to print detail of the instance
    pub fn to_string(&self) -> String {
        format!("GitHubSource user({}) repo ({}) file_name({}) access_token({}) version_needed({})",
                &self.user, &self.repo, &self.file_name, &self.access_token, &self.version_needed)
    }

    /// Function to read config from TOML
    fn read_config(&self) ->GitHubSource {
        let settings = Config::builder()
            // file name is "ExternalSourceConfig"
            .add_source(config::File::with_name("src/ExternalSourceConfig"))
            .build()
            .unwrap();

        // put details into a hashmap and create a new instance
        let args = settings.try_deserialize::<HashMap<String, String>>().unwrap();
        let version_needed = args.get("version_needed").unwrap();
        let experimental = args.get("experimental").unwrap();
        return GitHubSource::new(user,repo,file_name,access_token,version_needed,experimental);
    }

    /// Get all available version
    async fn get_versions(&self) -> Vec<String> {
        let octo = octocrab::OctocrabBuilder::new()
            .personal_token(self.access_token)
            .build()
            .unwrap();

        // pull all available version into a page
        let page = octo
            .repos(self.owner, self.repo_name)
            .releases()
            .list()
            .per_page(100)
            .page(1u32)
            .send()
            .await?;
        let mut versions:Vec<String> = Vec::new();
        for item in page.take_items(){
            println!("{}",item.tag_name);
            let tag_cleaned = item.tag_name.replace("v", "");
            // TODO: remove the "pre", filter unstable if experimental is false
            versions.push(tag_cleaned)
        };
        return versions;
    }

    /// Function to get latest version
    fn get_satisfied(&self) -> String {
        let req = Version::parse(&self.version_needed).unwrap();
        let mut output;
        // dependency resolution
        for version in &versions.rev() {
            // get version from the reverse order
            if Version::parse(&version).unwrap().matches(&req){
                // get the latest satisfying version
                output = version;
                break
            }
        }
        return output;
    }
}

/// Function to pull content from GitHub
impl Pull for GitHubSource {
    async fn pull(&self) -> octocrab::Result<ContentItems> {
        let octo = octocrab::OctocrabBuilder::new()
            .personal_token(self.access_token)
            .build()
            .unwrap();
        // the actual pull
        let repo = octo
            .repos(self.user, self.repo_name)
            .get_content()
            .path(self.file_name)
            .r#ref("master")
            .send()
            .await?;
        Ok(repo)
    }
}



