use async_trait::async_trait;
use crate::rules::errors::{Error};
#[async_trait]
pub trait AuthenticatedSource {
    async fn authenticate(&self)->Result<(),Error>;
    async fn check_authorization(&self)->Result<(),Error>;
    async fn change_detected(&self,local_metadata:String)->Result<bool,Error>;
    async fn pull(&self)-> Result<String,Error>;
}