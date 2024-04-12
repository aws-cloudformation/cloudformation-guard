use std::io::Cursor;

use anyhow::Context;
use cfn_guard::{
    commands::{
        validate::{OutputFormatType, ShowSummaryType},
        Executable,
    },
    utils::{
        reader::{ReadBuffer, Reader},
        writer::{WriteBuffer, Writer},
    },
    CommandBuilder, ValidateBuilder,
};

#[derive(Debug)]
pub struct Payload {
    pub data: String,
    pub rules: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let payload = r#"{"data": ["{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}","{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}"], "rules" : [ "Parameters.InstanceName == \"TestInstance\"","Parameters.InstanceName == \"TestInstance\"" ]}"#;
    let mut reader = Reader::new(ReadBuffer::Cursor(Cursor::new(Vec::from(
        payload.as_bytes(),
    ))));
    let mut writer = match Writer::new_with_err(WriteBuffer::Vec(vec![]), WriteBuffer::Vec(vec![]))
    {
        Ok(writer) => writer,
        Err(err) => {
            panic!("Error: {}", err);
        }
    };

    let cmd = ValidateBuilder::default()
        .payload(true)
        .output_format(OutputFormatType::JSON)
        .structured(true)
        .show_summary(vec![ShowSummaryType::None])
        .try_build()
        .context("failed to build validate command")?;

    cmd.execute(&mut writer, &mut reader)?;

    let content = writer.stripped().context("failed to read from writer")?;
    println!("{content}");

    Ok(())
}
