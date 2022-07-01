trait AuthenticatedSource {
    fn authenticate(&self);
    fn get_versions(&self);
    fn pull(&self);
}

impl<T> ExternalSource for T where T: AuthenticatedSource {
    fn process(&self) {
        self.authenticate();
        self.get_versions();
        self.pull();
    }
}