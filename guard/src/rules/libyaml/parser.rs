use crate::rules::{
    errors::Error,
    libyaml::{
        event::{convert_event, Event},
        util::system_mark_to_location,
        util::Owned,
    },
    path_value::Location,
    Result,
};

use std::{borrow::Cow, mem::MaybeUninit, ptr::addr_of_mut};

use unsafe_libyaml as sys;

pub(crate) struct Parser<'input> {
    pin: Owned<ParserPinned<'input>>,
}

struct ParserPinned<'input> {
    sys: sys::yaml_parser_t,
    input: Cow<'input, [u8]>,
}

impl<'input> Parser<'input> {
    pub fn new(input: Cow<'input, [u8]>) -> Parser<'input> {
        let owned = Owned::<ParserPinned>::new_uninit();
        let pin = unsafe {
            let parser = addr_of_mut!((*owned.ptr).sys);
            if sys::yaml_parser_initialize(parser).fail {
                panic!(
                    "malloc error: {}",
                    Error::ParseError("error parsing file".to_string())
                );
            }
            sys::yaml_parser_set_encoding(parser, sys::YAML_UTF8_ENCODING);
            sys::yaml_parser_set_input_string(parser, input.as_ptr(), input.len() as u64);
            addr_of_mut!((*owned.ptr).input).write(input);
            Owned::assume_init(owned)
        };
        Parser { pin }
    }

    pub fn next(&mut self) -> Result<(Event<'input>, Location)> {
        let mut event = MaybeUninit::<sys::yaml_event_t>::uninit();
        unsafe {
            let parser = addr_of_mut!((*self.pin.ptr).sys);
            if (&(*parser)).error != sys::YAML_NO_ERROR {
                return Err(Error::ParseError("error parsing file".to_string()));
            }
            let event = event.as_mut_ptr();
            if sys::yaml_parser_parse(parser, event).fail {
                return Err(Error::ParseError("error parsing file".to_string()));
            }
            let ret = convert_event(&*event, &(*self.pin.ptr).input);
            let location = system_mark_to_location((*event).start_mark);

            sys::yaml_event_delete(event);
            Ok((ret, location))
        }
    }
}

impl<'input> Drop for ParserPinned<'input> {
    fn drop(&mut self) {
        unsafe { sys::yaml_parser_delete(&mut self.sys) }
    }
}
