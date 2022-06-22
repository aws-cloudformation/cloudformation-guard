use config::Config;

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
}



