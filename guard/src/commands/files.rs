use std::cmp::Ordering;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::str::FromStr;

use walkdir::WalkDir;
use crate::rules::errors::Error;

pub(crate) fn read_file_content(file: File) -> Result<String, std::io::Error> {
    let mut file_content = String::new();
    let mut buf_reader = BufReader::new(file);
    buf_reader.read_to_string(&mut file_content)?;
    Ok(file_content)
}

pub(crate) fn get_files<F>(file: &str, sort: F) -> Result<Vec<PathBuf>, Error>
    where F: FnMut(&walkdir::DirEntry, &walkdir::DirEntry) -> Ordering + Send + Sync + 'static
{
    let path = PathBuf::from_str(file)?;
    let file = File::open(file)?;
    let metatdata = file.metadata()?;
    Ok(if metatdata.is_file() {
        vec![path]
    }
    else {
        let walkdir = WalkDir::new(path).follow_links(true)
            .sort_by(sort);
        let mut result = Vec::with_capacity(10);
        for file in walkdir {
            if let Ok(entry) = file {
                let path = entry.into_path();
                result.push(path);
            }
        }
        result
    })
}

pub(crate) fn alpabetical(first : &walkdir::DirEntry, second: &walkdir::DirEntry) -> Ordering {
    first.file_name().cmp(second.file_name())
}

pub(crate) fn last_modified(first: &walkdir::DirEntry, second: &walkdir::DirEntry) -> Ordering {
    if let Ok(first) = first.metadata() {
        if let Ok(second) = second.metadata() {
            if let Ok(first) = first.modified() {
                if let Ok(second) = second.modified() {
                    return first.cmp(&second)
                }
            }
        }
    }
    return Ordering::Equal
}

pub(crate) fn regular_ordering(_first: &walkdir::DirEntry, _second: &walkdir::DirEntry) -> Ordering {
    Ordering::Equal
}

