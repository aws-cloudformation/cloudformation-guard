use cfn_guard::ValidateInput;
use ffi_support::FfiStr;

#[repr(C)]
pub struct FfiValidateInput<'a> {
    pub data: FfiStr<'a>,
    pub file_name: FfiStr<'a>,
}

impl<'a> From<FfiValidateInput<'a>> for ValidateInput<'a> {
    fn from(input: FfiValidateInput<'a>) -> Self {
        ValidateInput {
            content: input.data.into(),
            file_name: input.file_name.into(),
        }
    }
}
