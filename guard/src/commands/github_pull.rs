use semver::{BuildMetadata, Prerelease, Version, VersionReq};
use octocrab;
use std::fs;
use async_trait::async_trait;
use crate::rules::errors::{Error, ErrorKind};
use crate::commands::authenticated_source::AuthenticatedSource;
use std::collections::HashMap;
use crate::commands::util::{read_config,validate_version};


/// This is a class for getting file from GitHub
pub struct GitHubSource {
    pub octocrab_instance: octocrab::Octocrab,
    pub user: String,
    pub repo: String,
    pub file_name: String,
    pub access_token: String,
    pub version_needed: String,
    pub experimental: bool,
    pub version_download: String,
    pub file_content: String
}

/// inheriting from authenticated source
#[async_trait]
impl AuthenticatedSource for GitHubSource{
    fn authenticate(&self)->Result<(),Error>{
        // let mut exit_code;
        self.octocrab_instance = octocrab::OctocrabBuilder::new()
        .personal_token(self.access_token)
        .build()
        .unwrap();
        let user = self.octocrab_instance.current().user();
        match user {
            Err(octocrab::Error::GitHubError) => return Err(Error::new(ErrorKind::AuthenticationError("Invalid GitHub credential"))),
            Ok(user)=>(),
        }
        Ok(())
    }



    fn check_authorization(&self)->Result<(),Error>{
        let mut exit_code;
        let tags = self.octocrab_instance.repos(self.owner, self.repo).list_tags().send();
        match tags {
            Err(octocrab::Error::GitHubError) => return Err(Error::new(ErrorKind::AuthenticationError("Invalid GitHub permission".to_string()))),
            Ok(tags)=>(),
        }
        Ok(())
    }


   fn change_detected(&self, local_metadata:String)->bool{
            let mut changed;
            let page = self.octocrab_instance
                .repos(self.owner, self.repo)
                .releases()
                .list()
                .send();
            Ok(page);
            let mut versions:HashMap<String,String> = HashMap::new();
            for item in page.take_items(){
                if self.experimental==false{
                    if item.prerelease {
                        continue;
                    }
                }
                let tag_cleaned = item.tag_name.replace("v", "");
                versions.insert(tag_cleaned, item.node_id);
            };
            self.version_download = self.get_most_correct_version(&versions);
            if self.version_download != local_metadata {
                changed = true;
            }
        return changed;
    }

    fn pull(&self) -> String{
        let repo = self.octocrab_instance
                .repos(self.user, self.repo)
                .get_content()
                .path(self.file_name)
                .r#ref(self.version_download)
                .send();
        Ok(repo);
        let contents = repo.take_items();
        let c = &contents[0];
        let data = c.decoded_content().unwrap();
        fs::create_dir_all("external-source/")?; // TODO: CONSTANT?
        // fs::create_dir_all("external-source/github")?; // TODO: log message
        // let file_path = concat!("external-source/github",file_name);
        let splitted_path:Vec<&str> = self.file_name.split("/").collect();
        let file_name = splitted_path.last();
        let file_path = format!("external-source/{}",file_name);
        fs::write(file_path, data).expect("Unable to write file");
        // let cache_path = concat!("external-source/github.toml");
        return file_path;
    }
}

/// Constructor and class method
impl GitHubSource {
    pub fn new(user: String, repo: String, file_name: String) -> Self {
        let configs = Self::validate_config();
        let credentials = Self::validate_credential();
        let access_token = credentials.get("api_token").unwrap();
        let version_needed = configs.get("version_needed").unwrap();
        let experimental = configs.get("experimental").unwrap();


        GitHubSource {
            octocrab_instance: (),
            user,
            repo,
            file_name,
            access_token: access_token,
            version_needed: version_needed,
            experimental: match experimental {
                 "true" => true,
                "false" => false,
            },
            version_download: (),
            file_content: ()
        }
    }

    // helper method to validate input
    pub fn validate_config()->HashMap<String,String>{
        let args = read_config("src/ExternalSourceConfig".to_string());
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

    pub fn validate_credential()->HashMap<String,String>{
        let args = read_config("src/ExternalSourceCredentials".to_string());
        let api_key = args.get("github_api").unwrap();
        if api_key.is_empty() || api_key.is_numeric(){
            return Err(Error::new(ErrorKind::StringValue("Version must be string")))
        }
        return args
    }

    /// Function to print detail of the instance
    pub fn to_string(self: &Self) -> String {
        format!("GitHubSource user({}) repo ({}) file_name({}) access_token({}) version_needed({})",
                &self.user, &self.repo, &self.file_name, &self.access_token, &self.version_needed)
    }


    /// Function to get latest version
    pub fn get_most_correct_version(self: &Self, versions:&HashMap<String,String>) -> String {
        let req = Version::parse(&self.version_needed).unwrap();
        let mut output;
        // dependency resolution
        let available_versions:Vec<String> = versions.keys().cloned().collect();
        for version in available_versions.rev() {
            // get version from the reverse order
            if Version::parse(&version).unwrap().matches(&req){
                // get the latest satisfying version
                output = versions.get(version);
                break
            }
        }
        return output;
    }
}




