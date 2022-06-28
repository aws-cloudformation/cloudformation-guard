use config::Config;
use semver::{BuildMetadata, Prerelease, Version, VersionReq};

pub struct GitHubSource {
    pub user: String,
    pub repo: String,
    pub file_name: String,
    pub access_token: String,
    pub version_needed: String
}

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

    pub fn to_string(&self) -> String {
        format!("GitHubSource user({}) repo ({}) file_name({}) access_token({}) version_needed({})",
                &self.user, &self.repo, &self.file_name, &self.access_token, &self.version_needed)
    }

    fn read_config(&self) ->GitHubSource {
        let settings = Config::builder()
            .add_source(config::File::with_name("src/config"))
            .build()
            .unwrap();

        let args = settings.try_deserialize::<HashMap<String, String>>().unwrap();
        let version_needed = args.get("version_needed").unwrap();
        let experimental = args.get("experimental").unwrap();
        return GitHubSource::new(user,repo,file_name,access_token,version_needed,experimental);
    }

    async fn get_version(&self) -> Vec<String> {
        let octo = octocrab::OctocrabBuilder::new()
            .personal_token(self.access_token)
            .build()
            .unwrap();

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

    fn get_satisfied(&self) -> String {
        let req = Version::parse(&self.version_needed).unwrap();
        let mut output;
        // dependency resolution
        for version in &versions.rev() {
            if Version::parse(&version).unwrap().matches(&req){
                output = version;
                break
            }
        }
        return output;
    }
}
impl Pull for GitHubSource {
    fn pull(&self) -> octocrab::Result<ContentItems> {
        let octo = octocrab::OctocrabBuilder::new()
            .personal_token(self.access_token)
            .build()
            .unwrap();
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



