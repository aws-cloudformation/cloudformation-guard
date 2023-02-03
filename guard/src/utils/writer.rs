use std::fs::File;
use std::io::{Read, Stdout, Write};
use std::string::FromUtf8Error;

pub struct Writer {
    buffer: WriteBuffer,
}

impl Writer {
    pub fn new(buffer: WriteBuffer) -> Self {
        Self { buffer }
    }

    pub fn into_string(self) -> Result<String, FromUtf8Error> {
        self.buffer.into_string()
    }

    pub fn stripped(self) -> Result<String, FromUtf8Error> {
        match self.buffer {
            WriteBuffer::Vec(vec) => String::from_utf8(strip_ansi_escapes::strip(&vec).unwrap()),
            WriteBuffer::File(mut file) => {
                let mut data = String::new();
                file.read_to_string(&mut data)
                    .expect("Unable to read from file");

                String::from_utf8(strip_ansi_escapes::strip(data).unwrap())
            }
            _ => unreachable!(),
        }
    }
}

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.write(String::from_utf8_lossy(buf).as_bytes())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.buffer.flush()
    }
}

pub enum WriteBuffer {
    Stdout(Stdout),
    Vec(Vec<u8>),
    File(File),
}

impl WriteBuffer {
    fn into_string(self) -> Result<String, FromUtf8Error> {
        match self {
            WriteBuffer::Stdout(..) => unimplemented!(),
            WriteBuffer::Vec(vec) => String::from_utf8(vec),
            WriteBuffer::File(mut file) => {
                let mut data = String::new();
                file.read_to_string(&mut data)
                    .expect("Unable to read from file");
                Ok(data)
            }
        }
    }
}

impl Write for WriteBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            WriteBuffer::Stdout(stdout) => stdout.write(buf),
            WriteBuffer::Vec(vec) => vec.write(buf),
            WriteBuffer::File(file) => file.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WriteBuffer::Stdout(stdout) => stdout.flush(),
            WriteBuffer::Vec(vec) => vec.flush(),
            WriteBuffer::File(file) => file.flush(),
        }
    }
}
