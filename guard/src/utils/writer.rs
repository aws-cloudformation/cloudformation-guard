use crate::rules::errors::InternalError::{
    FromUtf8Error, IncompatibleWriterError, UnsupportedBufferError, UnsupportedOperationError,
};
use crate::Error;
use std::fs::File;
use std::io::{Read, Stderr, Stdout, Write};

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
    pub fn new(buffer: WriteBuffer) -> crate::rules::Result<Self> {
        if buffer.is_err() {
            return Err(Error::from(IncompatibleWriterError(
                "Unable to use stderr as a regular buffer.".to_string(),
            )));
        }

        Ok(Self {
            buffer,
            err: WriteBuffer::Stderr(std::io::stderr()),
        })
    }

    pub fn new_with_err(buffer: WriteBuffer, err: WriteBuffer) -> crate::rules::Result<Self> {
        if buffer.is_err() {
            return Err(Error::from(IncompatibleWriterError(
                "Unable to use stderr as a regular buffer.".to_string(),
            )));
        }

        Ok(Self { buffer, err })
    }

    pub fn write_err(&mut self, s: String) -> std::io::Result<()> {
        writeln!(self.err, "{s}")
    }

    pub fn err_to_stripped(self) -> crate::rules::Result<String> {
        match self.err {
            WriteBuffer::Vec(vec) => String::from_utf8(strip_ansi_escapes::strip(vec)?)
                .map_err(|e| Error::from(FromUtf8Error(e))),
            WriteBuffer::File(mut file) => {
                let mut data = String::new();
                file.read_to_string(&mut data)
                    .expect("Unable to read from file");

                String::from_utf8(strip_ansi_escapes::strip(data)?)
                    .map_err(|e| Error::from(FromUtf8Error(e)))
            }
            WriteBuffer::Stdout(..) => Err(Error::from(UnsupportedOperationError(
                "Unable to call err_to_stripped() on a stdout buffer.".to_string(),
            ))),
            WriteBuffer::Stderr(..) => Err(Error::from(UnsupportedOperationError(
                "Unable to call err_to_stripped() on a stderr buffer.".to_string(),
            ))),
        }
    }

    pub fn into_string(self) -> crate::rules::Result<String> {
        self.buffer.into_string()
    }

    pub fn stripped(self) -> crate::rules::Result<String> {
        match self.buffer {
            WriteBuffer::Vec(vec) => {
                let stripped = strip_ansi_escapes::strip(vec)?;

                String::from_utf8(stripped).map_err(|e| Error::from(FromUtf8Error(e)))
            }
            WriteBuffer::File(mut file) => {
                let mut data = String::new();
                file.read_to_string(&mut data)
                    .expect("Unable to read from file");

                let stripped = strip_ansi_escapes::strip(data.into_bytes())?;

                String::from_utf8(stripped).map_err(|e| Error::from(FromUtf8Error(e)))
            }
            WriteBuffer::Stdout(..) => Err(Error::from(UnsupportedBufferError(
                "Unable to strip ANSI escapes from stdout buffer.".to_string(),
            ))),
            WriteBuffer::Stderr(..) => Err(Error::from(UnsupportedBufferError(
                "Unable to strip ANSI escapes from stderr buffer.".to_string(),
            ))),
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
    fn is_err(&self) -> bool {
        matches!(self, WriteBuffer::Stderr(_))
    }
    fn into_string(self) -> crate::rules::Result<String> {
        match self {
            WriteBuffer::Stdout(..) => Err(Error::from(UnsupportedOperationError(
                "Unable to call into_string() on a stdout buffer.".to_string(),
            ))),
            WriteBuffer::Stderr(..) => Err(Error::from(UnsupportedOperationError(
                "Unable to call into_string() on a stderr buffer.".to_string(),
            ))),
            WriteBuffer::Vec(vec) => {
                String::from_utf8(vec).map_err(|e| Error::from(FromUtf8Error(e)))
            }
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
