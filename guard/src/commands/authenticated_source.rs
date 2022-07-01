trait AuthenticatedSource {
    fn authenticate(&self);
    fn get_version(&self);
    fn pull(&self);
}

impl<T> ExternalSource for T where T: AuthenticatedSource {
    fn process(&self) {
        self.authenticate();
        self.get_version();
        self.pull();
    }
}