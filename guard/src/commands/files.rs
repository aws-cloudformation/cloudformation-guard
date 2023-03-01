use std::cmp::Ordering;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::str::FromStr;

use crate::rules::errors::Error;
use walkdir::{DirEntry, WalkDir};

pub(crate) fn read_file_content(file: File) -> Result<String, std::io::Error> {
    let mut file_content = String::new();
    let mut buf_reader = BufReader::new(file);
    buf_reader.read_to_string(&mut file_content)?;
    Ok(file_content)
}

pub(crate) fn get_files<F>(file: &str, sort: F) -> Result<Vec<PathBuf>, Error>
where
    F: FnMut(&walkdir::DirEntry, &walkdir::DirEntry) -> Ordering + Send + Sync + 'static,
{
    let path = PathBuf::from_str(file)?;
    let input_file = File::open(file)?;
    let metadata = input_file.metadata()?;
    Ok(if metadata.is_file() {
        vec![path]
    } else {
        let result = get_files_with_filter(file, sort, |entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| !name.ends_with("/"))
                .unwrap_or(false)
        })?;
        result
    })
}

pub(crate) fn get_files_with_filter<S, F>(
    file: &str,
    sort: S,
    filter: F,
) -> Result<Vec<PathBuf>, Error>
where
    S: FnMut(&walkdir::DirEntry, &walkdir::DirEntry) -> Ordering + Send + Sync + 'static,
    F: Fn(&walkdir::DirEntry) -> bool,
{
    let mut selected = Vec::with_capacity(10);
    let walker = WalkDir::new(file).sort_by(sort).into_iter();
    let dir_check = |entry: &DirEntry| {
        // select directories to traverse
        if entry.path().is_dir() {
            return true;
        }
        filter(entry)
    };
    for each in walker.filter_entry(dir_check) {
        //
        // We are ignoring errors here. TODO fix this later
        //
        if let Ok(entry) = each {
            if entry.path().is_file() {
                selected.push(entry.into_path());
            }
        }
    }
    Ok(selected)
}

#[derive(Debug)]
pub(crate) struct Iter<'i, T, C>
where
    C: Fn(String, &PathBuf) -> Result<T, Error>,
{
    files: &'i [PathBuf],
    index: usize,
    converter: C,
}

impl<'i, T, C> Iterator for Iter<'i, T, C>
where
    C: Fn(String, &PathBuf) -> Result<T, Error>,
{
    type Item = Result<T, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.files.len() {
            return None;
        }
        let next = &self.files[self.index];
        self.index += 1;
        let file = match File::open(next) {
            Ok(file) => file,
            Err(e) => return Some(Err(Error::from(e))),
        };
        let content = match read_file_content(file) {
            Ok(content) => content,
            Err(e) => return Some(Err(Error::from(e))),
        };
        Some((self.converter)(content, next))
    }
}

pub(crate) fn iterate_over<T, C>(files: &[PathBuf], converter: C) -> Iter<T, C>
where
    C: Fn(String, &PathBuf) -> Result<T, Error>,
{
    Iter {
        files,
        converter,
        index: 0,
    }
}

pub(crate) fn alpabetical(first: &walkdir::DirEntry, second: &walkdir::DirEntry) -> Ordering {
    first.file_name().cmp(second.file_name())
}

pub(crate) fn last_modified(first: &walkdir::DirEntry, second: &walkdir::DirEntry) -> Ordering {
    if let Ok(first) = first.metadata() {
        if let Ok(second) = second.metadata() {
            if let Ok(first) = first.modified() {
                if let Ok(second) = second.modified() {
                    return first.cmp(&second);
                }
            }
        }
    }
    return Ordering::Equal;
}

pub(crate) fn regular_ordering(
    _first: &walkdir::DirEntry,
    _second: &walkdir::DirEntry,
) -> Ordering {
    Ordering::Equal
}
