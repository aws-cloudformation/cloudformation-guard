use std::{
    ptr::NonNull,
    borrow::Cow,
    slice,
    fmt,
    fmt::Debug,
};
use crate::rules::libyaml::{
    tag::Tag,
    cstr::CStr,
    cstr,
};
use unsafe_libyaml as sys;

#[derive(Debug)]
pub(crate) enum Event<'input> {
    NoEvent,
    StreamStart,
    StreamEnd,
    DocumentStart,
    DocumentEnd,
    Alias(Anchor),
    Scalar(Scalar<'input>),
    SequenceStart(SequenceStart),
    SequenceEnd,
    MappingStart(MappingStart),
    MappingEnd,
}

pub(crate) unsafe fn convert_event<'input>(
    sys: &sys::yaml_event_t,
    input: &Cow<'input, [u8]>,
) -> Event<'input> {
    match sys.type_ {
        sys::YAML_STREAM_START_EVENT => Event::StreamStart,
        sys::YAML_STREAM_END_EVENT => Event::StreamEnd,
        sys::YAML_DOCUMENT_START_EVENT => Event::DocumentStart,
        sys::YAML_DOCUMENT_END_EVENT => Event::DocumentEnd,
        sys::YAML_ALIAS_EVENT => Event::Alias(optional_anchor(sys.data.alias.anchor).unwrap()),
        sys::YAML_SCALAR_EVENT => Event::Scalar(Scalar {
            anchor: optional_anchor(sys.data.scalar.anchor),
            tag: optional_tag(sys.data.scalar.tag),
            value: Box::from(slice::from_raw_parts(
                sys.data.scalar.value,
                sys.data.scalar.length as usize,
            )),
            style: match sys.data.scalar.style {
                sys::YAML_PLAIN_SCALAR_STYLE => ScalarStyle::Plain,
                sys::YAML_SINGLE_QUOTED_SCALAR_STYLE => ScalarStyle::SingleQuoted,
                sys::YAML_DOUBLE_QUOTED_SCALAR_STYLE => ScalarStyle::DoubleQuoted,
                sys::YAML_LITERAL_SCALAR_STYLE => ScalarStyle::Literal,
                sys::YAML_FOLDED_SCALAR_STYLE => ScalarStyle::Folded,
                sys::YAML_ANY_SCALAR_STYLE | _ => unreachable!(),
            },
            repr: if let Cow::Borrowed(input) = input {
                Some(&input[sys.start_mark.index as usize..sys.end_mark.index as usize])
            } else {
                None
            },
        }),
        sys::YAML_SEQUENCE_START_EVENT => Event::SequenceStart(SequenceStart {
            anchor: optional_anchor(sys.data.sequence_start.anchor),
            tag: optional_tag(sys.data.sequence_start.tag),
        }),
        sys::YAML_SEQUENCE_END_EVENT => Event::SequenceEnd,
        sys::YAML_MAPPING_START_EVENT => Event::MappingStart(MappingStart {
            anchor: optional_anchor(sys.data.mapping_start.anchor),
            tag: optional_tag(sys.data.mapping_start.tag),
        }),
        sys::YAML_MAPPING_END_EVENT => Event::MappingEnd,
        sys::YAML_NO_EVENT => Event::NoEvent,
        _ => unimplemented!(),
    }
}

pub(crate) struct Scalar<'input> {
    pub anchor: Option<Anchor>,
    pub tag: Option<Tag>,
    pub value: Box<[u8]>,
    pub style: ScalarStyle,
    pub repr: Option<&'input [u8]>,
}

#[derive(Debug)]
pub(crate) struct SequenceStart {
    pub anchor: Option<Anchor>,
    pub tag: Option<Tag>,
}

#[derive(Debug)]
pub(crate) struct MappingStart {
    pub anchor: Option<Anchor>,
    pub tag: Option<Tag>,
}

#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct Anchor(Box<[u8]>);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum ScalarStyle {
    Plain,
    SingleQuoted,
    DoubleQuoted,
    Literal,
    Folded,
}

unsafe fn optional_anchor(anchor: *const u8) -> Option<Anchor> {
    let ptr = NonNull::new(anchor as *mut i8)?;
    let cstr = CStr::from_ptr(ptr);
    Some(Anchor(Box::from(cstr.to_bytes())))
}

unsafe fn optional_tag(tag: *const u8) -> Option<Tag> {
    let ptr = NonNull::new(tag as *mut i8)?;
    let cstr = CStr::from_ptr(ptr);
    Some(Tag(Box::from(cstr.to_bytes())))
}

impl<'input> Debug for Scalar<'input> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let Scalar {
            anchor,
            tag,
            value,
            style,
            repr: _,
        } = self;

        struct LossySlice<'a>(&'a [u8]);

        impl<'a> Debug for LossySlice<'a> {
            fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                cstr::debug_lossy(self.0, formatter)
            }
        }

        formatter
            .debug_struct("Scalar")
            .field("anchor", anchor)
            .field("tag", tag)
            .field("value", &LossySlice(value))
            .field("style", style)
            .finish()
    }
}

impl Debug for Anchor {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        cstr::debug_lossy(&self.0, formatter)
    }
}
