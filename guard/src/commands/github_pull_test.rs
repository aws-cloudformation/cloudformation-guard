use super::super::*;
use super::*;

#[test]
fn test_create() {
   let gh = GitHubSource::new("a","b","c","d","e","f");
    assert_eq!(gh.user.to_string,"a");
}