use ffi_support::FfiStr;
use cfn_guard::ValidateInput;

#[repr(C)]
pub struct FfiValidateInput<'a> {
    pub content: FfiStr<'a>,
    pub file_name: FfiStr<'a>,
}

impl<'a> From<&FfiValidateInput<'a>> for ValidateInput<'a> {
    fn from(input : &FfiValidateInput<'a>) -> Self {
        let content = &input.content;
        let file_name = &input.file_name;

        ValidateInput {
            content: content.as_str(),
            file_name: file_name.as_str(),
        }
    }
}
