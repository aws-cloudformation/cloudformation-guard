use semver::{Version,VersionReq};
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
    async fn authenticate(&mut self)->Result<(),Error>{
        self.octocrab_instance = octocrab::OctocrabBuilder::new()
        .personal_token(self.access_token.to_string())
        .build()
        .unwrap();
        let user = self.octocrab_instance.current().user().await;
        match user {
            Err(_e) => return Err(Error::new(ErrorKind::AuthenticationError("Invalid GitHub credential".to_string()))),
            Ok(user)=>(),
        }
        Ok(())
    }

    async fn check_authorization(&self)->Result<(),Error>{
        let tags = self.octocrab_instance.repos(&self.user, &self.repo).list_tags().send().await;
        match tags  {
            Err(_e) => return Err(Error::new(ErrorKind::AuthenticationError("Invalid GitHub permission".to_string()))),
            Ok(tags)=>(),
        }
        Ok(())
    }

    async fn change_detected(&mut self, local_metadata:String)->Result<bool,Error>{
            let mut changed = false;
            let page = self.octocrab_instance
                .repos(&self.user, &self.repo)
                .releases()
                .list()
                .send()
                .await;
            let mut versions:HashMap<String,String> = HashMap::new();
            for item in page.unwrap().take_items(){
                if self.experimental==false{
                    if item.prerelease {
                        continue;
                    }
                }
                let tag_cleaned = item.tag_name.replace("v", "");
                versions.insert(tag_cleaned, item.tag_name);
            };
            let correct_version = self.get_most_correct_version(versions);
            // self.version_download = correct_version;
            // get the SHA tag of the release
            let tag_page = self.octocrab_instance
                .repos(&self.user, &self.repo)
                .list_tags()
                .send()
                .await;
            for tag in tag_page.unwrap().take_items(){
                if tag.name == correct_version {
                    self.version_download = tag.commit.sha.to_string();
                }
            };
            if self.version_download != local_metadata {
                changed = true;
            }
        Ok(changed)
    }

    async fn pull(&self) -> Result<String,Error>{
        let repo = self.octocrab_instance
                .repos(&self.user, &self.repo)
                .get_content()
                .path(&self.file_name)
                .r#ref("master")// should be .r#ref(&self.version_download)
                .send()
                .await;
        let contents = repo.unwrap().take_items();
        let c = &contents[0];
        let data = c.decoded_content().unwrap();
        let mut root_folder = String::new();
        root_folder += &"external-source/github/".to_string();
        root_folder += &self.repo.to_string();
        root_folder += "/";
        fs::create_dir_all(&root_folder)?;
        let splitted_path:Vec<&str> = self.file_name.split("/").collect();
        // get everything but the last string which is the file name
        let mut subfolder = String::new();
        subfolder += &root_folder.to_string();
        for subfolder_name in splitted_path.split_last().unwrap().1 {
            subfolder += subfolder_name;
            subfolder += "/";
            fs::create_dir_all(&subfolder)?;
        }
        let file_name = splitted_path.split_last().unwrap().0;
        let mut file_path = String::new();
        file_path += &subfolder.to_string();
        file_path += file_name;
        fs::write(&file_path, data).expect("Unable to write file");
        // let cache_path = concat!("external-source/github.toml");
        println!("Downloaded to {}",file_path);
        Ok(file_path)
    }
}

/// Constructor and class method
impl GitHubSource {
    pub fn new(user: String, repo: String, file_name: String) -> Self {
        let configs = Self::validate_config().unwrap();
        let credentials = Self::validate_credential().unwrap();
        let access_token = credentials.get("api_token").unwrap();
        let version_needed = configs.get("version_needed").unwrap();
        let experimental_str = configs.get("experimental").unwrap();
        let experimental: bool = match experimental_str.as_ref() {
            "true" => true,
            _ => false
        };


        GitHubSource {
            octocrab_instance: octocrab::OctocrabBuilder::new()
                .build()
                .unwrap(),
            user,
            repo,
            file_name,
            access_token: access_token.to_string(),
            version_needed: version_needed.to_string(),
            experimental: experimental,
            version_download: String::new(),
            file_content: String::new()
        }
    }

    // helper method to validate input
    pub fn validate_config()->Result<HashMap<String,String>,Error>{
        //TODO: use relative path
        let args = read_config("guard/src/ExternalSourceConfig".to_string());
        let version_needed = args.get("version_needed").unwrap();
        // if !validate_version(version_needed.to_string()){
        //     return Err(Error::new(ErrorKind::StringValue("Version must be in the appropriate format".to_string())))
        // }
        let experimental = args.get("experimental").unwrap();
        // if version_needed.is_empty() {
        //     return Err(Error::new(ErrorKind::StringValue("Version must be string".to_string())))
        // }
        // if !experimental.eq("true") || !experimental.eq("false"){
        // return Err(Error::new(ErrorKind::StringValue("Experimental must be true or false".to_string())))
        // }
        Ok(args)
    }

    pub fn validate_credential()->Result<HashMap<String,String>,Error>{
        let args = read_config("guard/src/ExternalSourceCredential".to_string());
        let api_key = args.get("api_token").unwrap();
        if api_key.is_empty(){
            return Err(Error::new(ErrorKind::StringValue("Version must be string".to_string())))
        }
        Ok(args)
    }

    /// Function to print detail of the instance
    pub fn to_string(self: &Self) -> String {
        format!("GitHubSource user({}) repo ({}) file_name({}) access_token({}) version_needed({})",
                &self.user, &self.repo, &self.file_name, &self.access_token, &self.version_needed)
    }


    /// Function to get latest version
    pub fn get_most_correct_version(self: &Self, versions:HashMap<String,String>) -> String {
        let req = VersionReq::parse(&self.version_needed).unwrap();
        let mut output:String = "".to_string();
        // dependency resolution
        let available_versions:Vec<String> = versions.keys().cloned().collect();
        for version in available_versions.iter().rev() {
            // get version from the reverse order
            let parsed_version = Version::parse(&version).unwrap();
            if req.matches(&parsed_version){
                // get the latest satisfying version
                output = versions.get(&version.to_string()).as_deref().unwrap().to_string();
                break
            }
        }
        return output;
    }

}




