use super::super::*;
use super::*;

#[test]
fn test_create() {
   let gh = GitHubSource::new("a","b","c","d","e","f");
    assert_eq!(gh.user.to_string,"a");
}

fn test_get_satisfied(){
    let versions = ["0.1.0", "0.1.1", "0.1.2"].iter().map(|&s| s.into()).collect();
    let gh = GitHubSource::new("a","b","c","d","e","0.1.0");
    assert_eq!(gh.get_satisfied(versions), "0.1.2");
}