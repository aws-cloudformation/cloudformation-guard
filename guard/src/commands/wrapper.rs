use std::io::{Stdout, Write};
use std::string::FromUtf8Error;

pub struct Writer {
    buffer: WriteBuffer,
}

impl Writer {
    pub fn new(buffer: WriteBuffer) -> Self {
        Self { buffer }
    }

    pub fn from_utf8(self) -> Result<String, FromUtf8Error> {
        self.buffer.from_utf8()
    }
}

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer
            .write(String::from_utf8_lossy(buf).as_bytes())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.buffer.flush()
    }
}

pub enum WriteBuffer {
    Stdout(Stdout),
    Vec(Vec<u8>),
}

impl WriteBuffer {
    fn from_utf8(self) -> Result<String, FromUtf8Error> {
        match self {
            WriteBuffer::Stdout(..) => unimplemented!(),
            WriteBuffer::Vec(vec) => String::from_utf8(vec),
        }
    }
}

impl Write for WriteBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            WriteBuffer::Stdout(stdout) => stdout.write(buf),
            WriteBuffer::Vec(vec) => vec.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WriteBuffer::Stdout(stdout) => stdout.flush(),
            WriteBuffer::Vec(vec) => vec.flush(),
        }
    }
}
