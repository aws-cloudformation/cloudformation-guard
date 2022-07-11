use semver::{BuildMetadata, Prerelease, Version, VersionReq};
use octocrab;
use crate::{SUCCESS_CODE,FAILURE_CODE};
use std::fs;


/// This is a class for getting file from GitHub
pub struct GitHubSource {
    pub octocrab_instance: octocrab::repos::RepoHandler::new(),
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
    async fn authenticate(&self)->Result<(),Error>{
        let mut exit_code;
        self.octocrab_instance = octocrab::OctocrabBuilder::new()
        .personal_token(self.access_token)
        .build()
        .unwrap();
        let user = self.octocrab_instance.current().user().await?;
        match user {
            Err(octocrab::Error::GitHubError) => return Err(Error::new(ErrorKind::AuthenticationError("Invalid GitHub credential"))),
            Ok(user) => exit_code = SUCCESS_CODE;
        }
    }
       Ok(exit_code)
    }

    async fn check_authorization(&self)->Result<(),Error>{
        let mut exit_code;
        let tags = self.octocrab_instance.repos(owner, repo_name).list_tags().send().await?;
        match user {
            Err(octocrab::Error::GitHubError) => return Err(Error::new(ErrorKind::AuthenticationError("Invalid GitHub permission"))),
            Ok(user) => exit_code = SUCCESS_CODE;
        }
            Ok(exit_code)
    }


   async fn change_detected(&self, local_metadata:String)->bool{
            let mut changed;
            let page = self.octo
                .repos(self.owner, self.repo_name)
                .releases()
                .list()
                .send()
                .await?;
            Ok(page);
            let mut versions:Vec<String> = Vec::new();
            for item in page.take_items(){
                if !self.experimental{
                    if item.prerelease {
                        continue;
                    }
                }
                tag_cleaned = item.tag_name.replace("v", "");
                versions.push(tag_cleaned)
            };
            self.version_download = self.get_most_correct_version(versions);
            if self.version_download != local_metadata {
                changed = true;
            }
        }
        return changed
    }

    fn pull(&self) -> String{
        let repo = self.octocrab_instance
                .repos(self.user, self.repo_name)
                .get_content()
                .path(self.file_name)
                .r#ref(self.version_download)
                .send()
                .await?;
        Ok(repo)
        let contents = repo.take_items();
        let c = &contents[0];
        let data = c.decoded_content().unwrap();
        fs::create_dir_all("external_src/")?;
        let file_path = concat!("external_src/",self.file_name);
        fs::write(file_path, data).expect("Unable to write file");
        return file_path;
    }
}

/// Constructor and class method
impl GitHubSource {
    pub fn new(user: String, repo: String, file_name: String) -> Self {
        let configs = validate_config();
        let credentials = validate_credential();


        GitHubSource {
            octocrab_instance: (),
            user,
            repo,
            file_name,
            access_token: credentials.get("github_api").unwrap(),
            version_needed:configs.get("version_needed").unwrap(),
            experimental: bool = match configs.get("experimental").unwrap() {
                 "true" => true,
                "false" => false,
            },
            version_download: (),
            file_content: ()
        }
    }

    // helper method to validate input
    pub fn validate_config(){
        let args = read_config("src/ExternalSourceConfig");
        let version_needed = args.get("version_needed").unwrap();
        if !validate_version(version_needed){
            return Err(Error::new(ErrorKind::StringValue("Version must be in the appropriate format")))
        }
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
        let api_key = args.get("github_api").unwrap();
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
    pub fn get_most_correct_version(&self, versions:&Vec<String>) -> String {
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




