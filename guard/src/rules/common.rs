
use super::values::Value;
use super::parser::Span;
use crate::errors::{Error, ErrorKind};

use nom::branch::alt;
use nom::bytes::complete::{tag, take_till};
use nom::character::complete::{char, multispace0, multispace1, space0};
use nom::combinator::{map, value};
use nom::multi::many0;
use nom::sequence::{preceded, delimited};
use nom::IResult;

use lazy_static::*;
use heck::{CamelCase, KebabCase, TitleCase, SnakeCase, MixedCase};

pub(in crate::rules) fn take_while_ws_or_comment(input: Span) -> IResult<Span, Vec<&str>> {
    many0(alt((value("", multispace1), comment)))(input)
}

pub(in crate::rules) fn white_space(ch: char) -> impl Fn(Span) -> IResult<Span, char> {
    move |input: Span| preceded(multispace0, char(ch))(input)
}

pub(in crate::rules) fn white_space_only(ch: char) -> impl Fn(Span) -> IResult<Span, char> {
    move |input: Span| preceded(space0, char(ch))(input)
}

pub(in crate::rules) fn white_space_tag(t: &str) -> impl Fn(Span) -> IResult<Span, &str> {
    let copy = String::from(t);
    move |input: Span| {
        map(preceded(multispace0, tag(copy.as_str())), |s: Span| {
            *s.fragment()
        })(input)
    }
}

pub(in crate::rules) fn white_space_only_tag(tag_: &str) -> impl Fn(Span) -> IResult<Span, Span> {
    let copy = String::from(tag_);
    move |input: Span| preceded(space0, tag(copy.as_str()))(input)
}

pub(in crate::rules) fn preceded_by(ch: char) -> impl Fn(Span) -> IResult<Span, char> {
    white_space(ch)
}

pub(in crate::rules) fn followed_by(ch: char) -> impl Fn(Span) -> IResult<Span, char> {
    white_space(ch)
}

pub(in crate::rules) fn preceded_by_space_only(ch: char) -> impl Fn(Span) -> IResult<Span, char> {
    white_space_only(ch)
}

pub(in crate::rules) fn followed_by_space_only(ch: char) -> impl Fn(Span) -> IResult<Span, char> {
    white_space(ch)
}

pub(in crate::rules) fn separated_by(ch: char) -> impl Fn(Span) -> IResult<Span, char> {
    white_space(ch)
}

pub(in crate::rules) fn separated_by_space_only(ch: char) -> impl Fn(Span) -> IResult<Span, char> {
    white_space_only(ch)
}

pub(in crate::rules) fn preceded_by_tag(tag: &str) -> impl Fn(Span) -> IResult<Span, &str> {
    white_space_tag(tag)
}

pub(in crate::rules) fn followed_by_tag(tag: &str) -> impl Fn(Span) -> IResult<Span, &str> {
    white_space_tag(tag)
}

pub(in crate::rules) fn separated_by_tag(tag: &str) -> impl Fn(Span) -> IResult<Span, &str> {
    white_space_tag(tag)
}

pub(in crate::rules) fn comment(input: Span) -> IResult<Span, &str> {
    map(preceded(char('#'), take_till(|c| c == '\n')), |s: Span| {
        *s.fragment()
    })(input)
}

pub(in crate::rules) fn comment_block<'a>(input: Span) -> IResult<Span, Vec<&str>> {
    many0(preceded(multispace0, comment))(input)
}

pub(crate) fn walk_value<'json>(in_val: &'json serde_json::Value, fields: &[String], hierarchy: String)
    -> std::result::Result<Vec<&'json serde_json::Value>, Error>
{
    let mut value = Some(in_val);
    let mut references = vec![];
    let mut hierarchy = hierarchy.clone();
    for (idx, field) in fields.iter().enumerate() {
        if *field == "*" {
            match value.unwrap() {
                serde_json::Value::Array(values) => {
                    for each in values.iter().enumerate() {
                        references.extend(walk_value(each.1,
                                                     &fields[idx+1..],
                                                     format!("{}/{}", &hierarchy, &each.0.to_string()))?);
                    }
                },
                serde_json::Value::Object(obj) => {
                    for each in obj.keys() {
                        hierarchy = hierarchy + "/" + each;
                        references.extend(walk_value(
                            obj.get(each).unwrap(),
                            &fields[idx+1..],
                            format!("{}/{}", &hierarchy, each))?);
                    }
                }
                _ => return Err(Error::new(ErrorKind::MissingProperty(
                    format!("Property {} in the hierarchy {}/{} does not exist",
                            field, &hierarchy, &(*fields).join("/")))))
            }
            return Ok(references)
        }

        hierarchy = format!("{}/{}", &hierarchy, field);
        value = match value.unwrap() {
            serde_json::Value::Object(obj) => {
                let cases: Vec<Box<dyn Fn(String) -> String>> = vec![
                    Box::new(|s: String| { s.to_camel_case() }),
                    Box::new(|s: String| { s.to_kebab_case() }),
                    Box::new(|s: String| { s.to_title_case() }),
                    Box::new(|s: String| { s.to_snake_case() }),
                    Box::new(|s: String| { s.to_mixed_case() }),
                ];
                let mut current = field.clone();
                let mut index = 0;
                let result = loop {
                    let inner = obj.get(&current);
                    if let None = inner {
                        if index < cases.len() {
                            current = cases[index](current);
                            index += 1;
                            continue;
                        }
                    }
                    break inner;
                };
                result
            },
            serde_json::Value::Array(values) => {
                let mut val = None;
                if let Ok(index) = (*field).parse::<usize>() {
                    if values.len() > index {
                        val = values.get(index)
                    }
                }
                val
            }
            _ => None
        };

        if value.is_none() {
            return Err(Error::new(ErrorKind::MissingProperty(
                format!("Property {} in hierarchy {} does not exist", &field, hierarchy))))
        }

    }
    references.push(value.unwrap());
    Ok(references)
}

pub(crate) fn walk_type_value<'a>(in_val: &'a Value, fields: &[String], hierarchy: String)
    -> Result<Vec<&'a Value>, Error> {

    let mut wrap = Ok(in_val);
    let mut references = vec![];
    let mut hierarchy = hierarchy.clone();
    for (idx, field) in fields.iter().enumerate() {
        if *field == "*" {
            match wrap.unwrap() {
                Value::List(list) => {
                    for (val_idx, each) in list.iter().enumerate() {
                        references.extend(
                            walk_type_value(each, &fields[idx + 1..],
                                            format!("{}/{}", &hierarchy, val_idx))?
                        )
                    }
                },

                Value::Map(map) => {
                    for (key, value) in map.iter() {
                        references.extend(
                            walk_type_value(value, &fields[idx+1..], format!("{}/{}", &hierarchy, key))?
                        )
                    }
                },

                _ => {
                    return Err(Error::new(ErrorKind::MissingProperty(
                        format!("use of wild '*' value in path {}, does not map to a list or map", &hierarchy)
                    )))
                }

            }
            return Ok(references)
        }

        hierarchy = format!("{}/{}", &hierarchy, field);
        wrap = match wrap.unwrap() {
            Value::Map(map) => {
                    let cases: Vec<Box<dyn Fn(String) -> String>> = vec![
                        Box::new(|s: String| { s.to_camel_case() }),
                        Box::new(|s: String| { s.to_kebab_case() }),
                        Box::new(|s: String| { s.to_title_case() }),
                        Box::new(|s: String| { s.to_snake_case() }),
                        Box::new(|s: String| { s.to_mixed_case() }),
                    ];
                    let mut current = field.clone();
                    let mut index = 0;
                    let result = loop {
                        let inner = map.get(&current);
                        if let None = inner {
                            if index < cases.len() {
                                current = cases[index](current);
                                index += 1;
                                continue;
                            }
                        }
                        break inner;
                    };
                    if let Some(val) = result {
                        Ok(val)
                    } else {
                        Err(Error::new(ErrorKind::MissingVariable(
                            format!("We are accessing field or index on a scalar value at {}", &hierarchy))))
                    }
                },

            Value::List(list) =>
                if let Ok(index) = (*field).parse::<usize>() {
                    if list.len() > index {
                        Ok(list.get(index).unwrap())
                    }
                    else {
                        Err(Error::new(ErrorKind::MissingProperty(
                            format!("Accessing an array index at {}, is larger than the array {}", index, list.len())
                        )))
                    }
                } else {
                    Err(Error::new(ErrorKind::MissingProperty(
                        format!("Could not convert into integer to for at {}", &hierarchy)
                    )))
                },

            _ =>
                Err(Error::new(ErrorKind::MissingProperty(
                format!("We are accessing field or index on a scalar value at {}", &hierarchy)
            )))
        };

        if wrap.is_err() {
            return Err(wrap.err().unwrap());
        }
    }
    references.push(wrap.unwrap());
    Ok(references)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::rules::parser::from_str;
    use std::collections::HashMap;

    #[test]
    fn test_walk_property() {
        let object = r###"
        {
             "index": 10,
             "nested": {
                 "inner": 10,
                 "inner_array": [10, 20]
             },
             "array": [
                 {
                     "array_inner": 20
                 },
                 {
                     "array_inner": 10
                 }
             ]
        }
        "###;

        let value = serde_json::from_str::<serde_json::Value>(object).unwrap();
        let property = walk_value(&value, &["index".to_string()], String::new()).unwrap();
        assert_eq!(*property[0],
                   serde_json::Value::Number(serde_json::Number::from(10usize)));
        let fields: Vec<String> = ["array", "*", "array_inner"].iter().map(|s| (*s).to_string()).collect();
        let property = walk_value(&value, &fields, String::new()).unwrap();
        assert_eq!(property.len(), 2);
        assert_eq!(property[0].as_i64(), Some(20i64));
        assert_eq!(property[1].as_i64(), Some(10i64));
        let fields: Vec<String> = ["nested", "inner_array", "*"].iter().map(|s| (*s).to_string()).collect();
        let property = walk_value(&value, &fields, String::new()).unwrap();
        assert_eq!(property.len(), 2);
        assert_eq!(property[0].as_i64(), Some(10i64));
        assert_eq!(property[1].as_i64(), Some(20i64));
        let property = walk_value(&value, &[], String::new()).unwrap();
        assert_eq!(property.len(), 1);
        assert_eq!(property[0], &value);
        let property = walk_value(&value, &["array".to_string(), "0".to_string()], String::new()).unwrap();
        assert_eq!(property.len(), 1);
        match property[0] {
            serde_json::Value::Object(map) => {
                assert_eq!(map.contains_key("array_inner"), true);
                assert_eq!(map.get("array_inner").unwrap().as_i64(), Some(20i64));
            }
            _ => unreachable!()
        }
        let property = walk_value(&value, &["*".to_string()], String::new()).unwrap();
        assert_eq!(property.len(), 3);
        assert_ne!(property.iter().find(|v| match **v { serde_json::Value::Number(_) => true, _ => false}), None);
    }

    #[test]
    fn test_walk_template() {
        let iam_template = r#"
Resources:
  LambdaRoleHelper:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - ec2.amazonaws.com
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service:
                - ec2.amazonaws.com
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service:
                - ec2.amazonaws.com
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'
"#;
        let cfn_template: HashMap<String, serde_json::Value> =
            serde_yaml::from_str(&iam_template).unwrap();
        let root = &cfn_template["Resources"]["LambdaRoleHelper"]["Properties"];
        let wildcard: Vec<String> = "AssumeRolePolicyDocument.Statement.*.Effect".split(".")
            .into_iter().map(|s| s.to_string()).collect();
        let values = walk_value(root, &wildcard,
                                String::from("Resources/LambdaRoleHelper/Properties"));
        assert_eq!(values.is_ok(), true);
        let collected = values.unwrap();
        assert_eq!(collected.len(), 3);
        for each in collected.iter() {
            match *each {
                serde_json::Value::String(name) => {
                    assert_eq!(name.as_str(), "Allow");
                }
                _ => unreachable!()
            }
        }
        let wildcard: Vec<String> = "AssumeRolePolicyDocument.Statement.*.Principal".split(".")
            .into_iter().map(|s| s.to_string()).collect();
        let values = walk_value(root, &wildcard,
                                String::from("Resources/LambdaRoleHelper/Properties"));
        assert_eq!(values.is_ok(), true);
        let collected = values.unwrap();
        assert_eq!(collected.len(), 3);
        for each in collected.iter() {
            match *each {
                serde_json::Value::Object(map) => {
                    assert_eq!(map.contains_key("Service"), true);
                    let principals = map.get("Service").unwrap();
                    assert_eq!(*principals, serde_json::Value::Array(
                        vec![
                            serde_json::Value::String(String::from("ec2.amazonaws.com")),
                            serde_json::Value::String(String::from("lambda.amazonaws.com")),
                        ]
                    ));
                },
                _ => unreachable!()
            }
        }
    }

    #[test]
    fn test_errors_walk_property() {
        let object = r###"
        {
             "index": 10,
             "nested": {
                 "inner": 10,
                 "inner_array": [10, 20]
             },
             "array": [
                 {
                     "array_inner": 20
                 },
                 {
                     "array_inner": 10
                 }
             ]
        }
        "###;

        let value = serde_json::from_str::<serde_json::Value>(object).unwrap();
        let path = &["index".to_string(), "not_there".to_string()];
        let err = match walk_value(&value, path, String::new()).unwrap_err() {
            Error(ErrorKind::MissingProperty(m)) => m,
            _ => unreachable!()
        };
        let msg = format!("Property {} in hierarchy {} does not exist", "not_there", "/index/not_there");
        assert_eq!(err, msg)
    }

    #[test]
    fn test_walk_multiple_case() -> Result<(), Error> {
        let context = r###"
{
  "AWS::S3::Bucket": {
    "BucketName": "This-Is-Encrypted",
    "BucketEncryption": {
      "ServerSideEncryptionConfiguration": [
        {
          "ServerSideEncryptionByDefault": {
            "SSEAlgorithm": "aws:kms",
            "KMSMasterKeyID": "kms-xxx-1234"
          }
        },
        {
          "ServerSideEncryptionByDefault": {
            "SSEAlgorithm": "aws:kms",
            "KMSMasterKeyID": "kms-yyy-1234"
          }
        }
      ]
    }
  }
}
        "###;

        let value = serde_json::from_str::<serde_json::Value>(context)?;
        let path = &["AWS::S3::Bucket".to_string(), "bucket_name".to_string()];
        let result = walk_value(&value, path, "/".to_string())?;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], &serde_json::Value::String("This-Is-Encrypted".to_string()));

        let path = &["AWS::S3::Bucket".to_string(),
                                 "bucket_encryption".to_string(),
                                 "server_side_encryption_configuration".to_string(),
                                 "*".to_string(),
                                 "server_side_encryption_by_default".to_string()];
        let result = walk_value(&value, path, "/".to_string())?;
        assert_eq!(result.len(), 2);
        let mut map = serde_json::Map::new();
        map.insert("SSEAlgorithm".to_string(),serde_json::Value::String("aws:kms".to_string()));
        map.insert("KMSMasterKeyID".to_string(), serde_json::Value::String("kms-xxx-1234".to_string()));
        assert_eq!(result[0], &serde_json::Value::Object(map));

        let path = &["AWS::S3::Bucket".to_string(), "bucket".to_string()];
        let result = walk_value(&value, path, "/".to_string());
        assert_eq!(result.is_err(), true);
        Ok(())
    }

    #[test]
    fn comment_test() {
        let s = "# this is a comment\n";
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len() - 1, 1, "\n", "") };
        assert_eq!(
            comment(from_str(s)),
            Ok((cmp_span, " this is a comment"))
        );
        let s = "# this is a incomplete comment no newline but of file";
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            comment(from_str(s)),
            Ok((
                cmp_span,
                " this is a incomplete comment no newline but of file"
            ))
        );
        let s1 = "# this is multiple";
        let s2 = "\n#this is next";
        let s = s1.to_owned() + s2;
        let cmp_span = unsafe { Span::new_from_raw_offset(s1.len(), 1, s2, "") };
        assert_eq!(
            comment(from_str(&s)),
            Ok((cmp_span, " this is multiple"))
        );
        let cmp_span = unsafe { Span::new_from_raw_offset(s2.len() + s1.len(), 2, "", "") };
        assert_eq!(
            comment_block(from_str(&s)),
            Ok((cmp_span, vec![" this is multiple", "this is next"]))
        );
    }

    #[test]
    fn take_while_ws_or_comment_test() {
        let s = r###"


        # this is a comment
        # this is a comment
        1234
"###;
        let cmp = take_while_ws_or_comment(from_str(&s));
        assert_eq!("1234\n", *cmp.unwrap().0.fragment());
        let s = "#this is the first\n#this is the second";
        let cmp = take_while_ws_or_comment(from_str(s));
        let span = unsafe { Span::new_from_raw_offset(s.len(), 2, "", "") };
        assert_eq!(cmp.unwrap().0, span)
    }

    #[test]
    fn take_while_test_3() {
        let s = "size in r[10, 10]";
        let cmp = take_while_ws_or_comment(from_str(s));
        assert_eq!(cmp.is_err(), false);
        assert_eq!(from_str(s), cmp.unwrap().0);
    }
}
