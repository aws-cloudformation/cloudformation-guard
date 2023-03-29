use crate::rules::libyaml::cstr;
use std::{
    fmt::{self, Debug},
    ops::Deref,
};

#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct Tag(pub(in crate::rules::libyaml) Box<[u8]>);

impl Tag {
    fn as_string(&self) -> String {
        match std::str::from_utf8(&self.0) {
            Ok(s) => s.to_string(),
            Err(_) => "".to_string(),
        }
    }

    pub(crate) fn get_handle(&self) -> String {
        self.as_string()
            .chars()
            .take_while(|c| *c == '!')
            .fold(String::new(), |mut handle, c| {
                handle.push(c);
                handle
            })
    }

    /// Returns the suffix of a given tag
    /// # Arguments
    /// * `offset` - A usize indicating the number of characters which belong to the prefix
    ///
    pub(crate) fn get_suffix(&self, offset: usize) -> String {
        self.as_string()
            .chars()
            .enumerate()
            .filter(|(i, _)| i >= &offset)
            .fold(String::new(), |mut suffix, (_, c)| {
                suffix.push(c);
                suffix
            })
    }
}

impl PartialEq<str> for Tag {
    fn eq(&self, other: &str) -> bool {
        *self.0 == *other.as_bytes()
    }
}

impl Deref for Tag {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for Tag {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        cstr::debug_lossy(&self.0, formatter)
    }
}
