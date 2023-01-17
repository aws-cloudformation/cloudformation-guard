use std::io::{Stdout, Write};

pub struct Wrapper {
    inner: WrappedType,
}

impl Wrapper {
    pub(crate) fn new(inner: WrappedType) -> Self {
        Self { inner }
    }
}

impl Write for Wrapper {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner
            .write(String::from_utf8_lossy(buf).as_bytes())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub enum WrappedType {
    Stdout(Stdout),
    Vec(Vec<u8>),
}

impl Write for WrappedType {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            WrappedType::Stdout(stdout) => stdout.write(buf),
            WrappedType::Vec(vec) => vec.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WrappedType::Stdout(stdout) => stdout.flush(),
            WrappedType::Vec(vec) => vec.flush(),
        }
    }
}
