trait AuthenticatedSource {
    // TODO: success or failure
    async fn authenticate(&self)-> i32;

    async fn authorize(&self)-> i32;
    // TODO:check cache to see if versioning is there
    // true or false
    fn change_detected(&self)->bool; // TODO: rename change_detected
    // TODO: true or false, conditional on get_version
    async fn pull(&self);
}