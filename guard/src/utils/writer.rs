use std::fs::File;
use std::io::{Read, Stderr, Stdout, Write};
use std::string::FromUtf8Error;

#[derive(Debug)]
pub struct Writer {
    buffer: WriteBuffer,
    err: WriteBuffer,
}

impl Default for Writer {
    fn default() -> Self {
        Self {
            buffer: WriteBuffer::Stdout(std::io::stdout()),
            err: WriteBuffer::Stderr(std::io::stderr()),
        }
    }
}

impl Writer {
    pub fn new(buffer: WriteBuffer) -> Self {
        if let WriteBuffer::Stderr(_) = buffer {
            panic!("unable to use stderr as regular buffer");
        }

        Self {
            buffer,
            err: WriteBuffer::Stderr(std::io::stderr()),
        }
    }

    pub fn new_with_err(buffer: WriteBuffer, err: WriteBuffer) -> Self {
        if let WriteBuffer::Stderr(_) = buffer {
            panic!("unable to use stderr as regular buffer");
        }

        Self { buffer, err }
    }

    pub fn write_err(&mut self, s: String) -> std::io::Result<()> {
        writeln!(self.err, "{s}")
    }

    pub fn err_to_stripped(self) -> Result<String, FromUtf8Error> {
        match self.err {
            WriteBuffer::Vec(vec) => String::from_utf8(strip_ansi_escapes::strip(vec).unwrap()),
            WriteBuffer::File(mut file) => {
                let mut data = String::new();
                file.read_to_string(&mut data)
                    .expect("Unable to read from file");

                String::from_utf8(strip_ansi_escapes::strip(data).unwrap())
            }
            _ => unreachable!(),
        }
    }

    pub fn into_string(self) -> Result<String, FromUtf8Error> {
        self.buffer.into_string()
    }

    pub fn stripped(self) -> Result<String, FromUtf8Error> {
        match self.buffer {
            WriteBuffer::Vec(vec) => String::from_utf8(strip_ansi_escapes::strip(vec).unwrap()),
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

#[derive(Debug)]
pub enum WriteBuffer {
    Stdout(Stdout),
    Vec(Vec<u8>),
    File(File),
    Stderr(Stderr),
}

impl WriteBuffer {
    fn into_string(self) -> Result<String, FromUtf8Error> {
        match self {
            WriteBuffer::Stdout(..) => unimplemented!(),
            WriteBuffer::Stderr(..) => unimplemented!(),
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
            WriteBuffer::Stderr(stderr) => stderr.write(buf),
            WriteBuffer::Vec(vec) => vec.write(buf),
            WriteBuffer::File(file) => file.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WriteBuffer::Stdout(stdout) => stdout.flush(),
            WriteBuffer::Stderr(stderr) => stderr.flush(),
            WriteBuffer::Vec(vec) => vec.flush(),
            WriteBuffer::File(file) => file.flush(),
        }
    }
}
