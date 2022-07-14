use async_trait::async_trait;
#[async_trait]
pub trait AuthenticatedSource {
    fn authenticate(&self)-> i32;
    fn check_authorization(&self)-> i32;
    fn change_detected(&self,local_metadata:String)->bool;
    fn pull(&self);
}