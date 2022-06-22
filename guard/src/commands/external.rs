pub trait External {
    fn pull(&self) -> octocrab::Result<ContentItems>;
}