use std::fs::File;
use std::io::{Cursor, Read, Stdin};

pub struct Reader {
    inner: ReadBuffer,
}

impl Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.inner {
            ReadBuffer::Stdin(stdin) => stdin.read(buf),
            ReadBuffer::Cursor(cursor) => cursor.read(buf),
            ReadBuffer::File(file) => file.read(buf),
        }
    }
}

impl Reader {
    pub fn new(stdin: ReadBuffer) -> Self {
        Self { inner: stdin }
    }
}

pub enum ReadBuffer {
    Stdin(Stdin),
    Cursor(Cursor<Vec<u8>>),
    File(File),
}
