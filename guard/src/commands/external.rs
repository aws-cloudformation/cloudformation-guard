pub trait Pull {
    fn pull(&self) -> octocrab::Result<ContentItems>;
}