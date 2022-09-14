use crate::rules::{
    libyaml::{
        cstr::CStr,
        util::system_mark_to_location
    },
    path_value::Location,
};
use std::{
    fmt::{self, Debug, Display},
    ptr::NonNull,
};
use unsafe_libyaml as sys;

pub(crate) type Result<T> = std::result::Result<T, Error>;

pub(crate) struct Error {
    kind: sys::yaml_error_type_t,
    problem: CStr<'static>,
    problem_offset: u64,
    problem_location: Location,
    context: Option<CStr<'static>>,
    context_location: Location,
}

impl Error {
    pub unsafe fn parse_error(parser: *const sys::yaml_parser_t) -> Self {
        Error {
            kind: (*parser).error,
            problem: match NonNull::new((*parser).problem as *mut _) {
                Some(problem) => CStr::from_ptr(problem),
                None => CStr::from_bytes_with_nul(b"libyaml parser failed but there is no error\0"),
            },
            problem_offset: (*parser).problem_offset,
            problem_location: system_mark_to_location((*parser).problem_mark),
            context: match NonNull::new((*parser).context as *mut _) {
                Some(context) => Some(CStr::from_ptr(context)),
                None => None,
            },
            context_location: system_mark_to_location((*parser).context_mark),
        }
    }
}

impl Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}", self.problem)?;
        if self.problem_location.line != 0 || self.problem_location.col != 0 {
            write!(formatter, " at {}", self.problem_location)?;
        } else if self.problem_offset != 0 {
            write!(formatter, " at position {}", self.problem_offset)?;
        }
        if let Some(context) = &self.context {
            write!(formatter, ", {}", context)?;
            if (self.context_location.line != 0 || self.context_location.col != 0)
                && (self.context_location.line != self.problem_location.line
                || self.context_location.col != self.problem_location.col)
            {
                write!(formatter, " at {}", self.context_location)?;
            }
        }
        Ok(())
    }
}

impl Debug for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let mut formatter = formatter.debug_struct("Error");
        if let Some(kind) = match self.kind {
            sys::YAML_MEMORY_ERROR => Some("MEMORY"),
            sys::YAML_READER_ERROR => Some("READER"),
            sys::YAML_SCANNER_ERROR => Some("SCANNER"),
            sys::YAML_PARSER_ERROR => Some("PARSER"),
            sys::YAML_COMPOSER_ERROR => Some("COMPOSER"),
            sys::YAML_WRITER_ERROR => Some("WRITER"),
            sys::YAML_EMITTER_ERROR => Some("EMITTER"),
            _ => None,
        } {
            formatter.field("kind", &format_args!("{}", kind));
        }
        formatter.field("problem", &self.problem);
        if self.problem_location.line != 0 || self.problem_location.col != 0 {
            formatter.field("problem_mark", &self.problem_location);
        } else if self.problem_offset != 0 {
            formatter.field("problem_offset", &self.problem_offset);
        }
        if let Some(context) = &self.context {
            formatter.field("context", context);
            if self.context_location.line != 0 || self.context_location.col != 0 {
                formatter.field("context_mark", &self.context_location);
            }
        }
        formatter.finish()
    }
}