use semver::{BuildMetadata, Prerelease, Version, VersionReq};
use octocrab;

/// This is a class for getting file from GitHub
pub struct GitHubSource {
    pub octo: octocrab::repos::RepoHandler::new(),
    pub user: String,
    pub repo: String,
    pub file_name: String,
    pub access_token: String,
    pub version_needed: String,
    pub experimental: String,
    pub version_download: String::new(),
    pub file_content: String::new()
}

/// inheriting from authenticated source
impl AuthenticatedSource for GitHubSource {
    fn authenticate(&self){
        self.octo = octocrab::OctocrabBuilder::new()
        .personal_token(self.access_token)
        .build()
        .unwrap();
    }

    fn get_version(&self){
        // pull all available version into a page
        let page = self.octo
            .repos(self.owner, self.repo_name)
            .releases()
            .list()
            .per_page(100)
            .page(1u32)
            .send()
            .await?;
        let mut versions:Vec<String> = Vec::new();
        for item in page.take_items(){
            let tag_cleaned = item.tag_name.replace("v", "");
            // TODO: remove the "pre", filter unstable if experimental is false
            versions.push(tag_cleaned)
        };
        self.version_download = self.get_satisfied(versions);
    }

    fn pull(&self){
        let repo = self.octo
            .repos(self.user, self.repo_name)
            .get_content()
            .path(self.file_name)
            .r#ref(self.version_download)
            .send()
            .await?;
        Ok(repo)
    }

}

/// Constructor and class method
impl GitHubSource {
    pub fn new(user: String, repo: String, file_name: String) -> Self {
        let configs = validate_config();
        let credentials = validate_credential();

        GitHubSource {
            octo: (),
            user,
            repo,
            file_name,
            access_token: credentials.get("API_key").unwrap(),
            version_needed:configs.get("version_needed").unwrap(),
            experimental: configs.get("experimental").unwrap(),
            version_download: (),
            file_content: ()
        }
    }

    // helper method to validate input
    pub fn validate_config(){
        let args = read_config("src/ExternalSourceConfig");
        let version_needed = args.get("version_needed").unwrap();
        let experimental = args.get("experimental").unwrap();
        if version_needed.is_empty() || version_needed.is_numeric(){
            return Err(Error::new(ErrorKind::StringValue("Version must be string")))
        }
        if !experimental.eq("true") || !experimental.eq("false"){
        return Err(Error::new(ErrorKind::StringValue("Experimental must be true or false")))
        }
        return args
    }

    pub fn validate_credential(){
        let args = read_config("src/ExternalSourceCredentials");
        let api_key = args.get("API_key").unwrap();
        if api_key.is_empty() || api_key.is_numeric(){
            return Err(Error::new(ErrorKind::StringValue("Version must be string")))
        }
        return args
    }

    /// Function to print detail of the instance
    pub fn to_string(&self) -> String {
        format!("GitHubSource user({}) repo ({}) file_name({}) access_token({}) version_needed({})",
                &self.user, &self.repo, &self.file_name, &self.access_token, &self.version_needed)
    }



    /// Function to get latest version
    pub fn get_satisfied(&self, versions:&Vec<String>) -> String {
        let req = Version::parse(&self.version_needed).unwrap();
        let mut output;
        // dependency resolution
        for version in versions.rev() {
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




