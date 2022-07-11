trait AuthenticatedSource {
    async fn authenticate(&self)-> i32;
    async fn authorize(&self)-> i32;
    fn change_detected(&self)->bool;
    async fn pull(&self);
}