use std::{convert::TryFrom, rc::Rc};

use crate::rules::{
    eval_context::eval_context_tests::BasicQueryTesting,
    exprs::AccessQuery,
    functions::converters::{parse_boolean, parse_float, parse_int, parse_string},
    path_value::PathAwareValue,
    EvalContext, QueryResult,
};

#[test]
fn test_parse_int() -> crate::rules::Result<()> {
    let value_str = r#"
    Resources:
      SecurityGroup:
        Type: AWS::EC2::SecurityGroup
        Properties:
          SecurityGroupIngress:
            String: "2456"
            Bool: true
            Char: '1'
            Int: 1
            Float: 1.0
            BadValue: "123 not a real number"
    "#;

    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;

    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };

    let string_query = AccessQuery::try_from(
        r#"Resources[ Type == 'AWS::EC2::SecurityGroup' ].Properties.SecurityGroupIngress.String"#,
    )?;

    let results = eval.query(&string_query.query)?;
    match results[0].clone() {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => {
            assert!(matches!(&*val, PathAwareValue::String(_)));
        }
        _ => unreachable!(),
    }

    let integer = parse_int(&results)?;
    assert!(matches!(
        integer[0].as_ref().unwrap(),
        PathAwareValue::Int((_, 2456))
    ));

    let bool_query = AccessQuery::try_from(
        r#"Resources[ Type == 'AWS::EC2::SecurityGroup' ].Properties.SecurityGroupIngress.Bool"#,
    )?;
    let results = eval.query(&bool_query.query)?;
    match results[0].clone() {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => {
            assert!(matches!(&*val, PathAwareValue::Bool(_)));
        }
        _ => unreachable!(),
    }

    let integer = parse_int(&results)?;
    assert!(matches!(
        integer[0].as_ref().unwrap(),
        PathAwareValue::Int((_, 1))
    ));

    let char_query = AccessQuery::try_from(
        r#"Resources[ Type == 'AWS::EC2::SecurityGroup' ].Properties.SecurityGroupIngress.Char"#,
    )?;
    let results = eval.query(&char_query.query)?;
    match results[0].clone() {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => {
            assert!(matches!(&*val, PathAwareValue::String(_)));
        }
        _ => unreachable!(),
    }

    let integer = parse_int(&results)?;
    assert!(matches!(
        integer[0].as_ref().unwrap(),
        PathAwareValue::Int((_, 1))
    ));

    let int_query = AccessQuery::try_from(
        r#"Resources[ Type == 'AWS::EC2::SecurityGroup' ].Properties.SecurityGroupIngress.Int"#,
    )?;
    let results = eval.query(&int_query.query)?;
    match results[0].clone() {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => {
            assert!(matches!(&*val, PathAwareValue::Int(_)));
        }
        _ => unreachable!(),
    }

    let integer = parse_int(&results)?;
    assert!(matches!(
        integer[0].as_ref().unwrap(),
        PathAwareValue::Int((_, 1))
    ));

    let float_query = AccessQuery::try_from(
        r#"Resources[ Type == 'AWS::EC2::SecurityGroup' ].Properties.SecurityGroupIngress.Float"#,
    )?;
    let results = eval.query(&float_query.query)?;
    match results[0].clone() {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => {
            assert!(matches!(&*val, PathAwareValue::Float(_)));
        }
        _ => unreachable!(),
    }

    let integer = parse_int(&results)?;
    assert!(matches!(
        integer[0].as_ref().unwrap(),
        PathAwareValue::Int((_, 1))
    ));

    let bad_value_query = AccessQuery::try_from(
        r#"Resources[ Type == 'AWS::EC2::SecurityGroup' ].Properties.SecurityGroupIngress.BadValue"#,
    )?;

    let results = eval.query(&bad_value_query.query)?;
    match results[0].clone() {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => {
            assert!(matches!(&*val, PathAwareValue::String(_)));
        }
        _ => unreachable!(),
    }

    let integer = parse_int(&results);
    assert!(integer.is_err());

    Ok(())
}

#[test]
fn test_parse_float() -> crate::rules::Result<()> {
    let value_str = r#"
    Resources:
      SecurityGroup:
        Type: AWS::EC2::SecurityGroup
        Properties:
          SecurityGroupIngress:
            String: "2.0"
            Int: 1
            Float: 1.0
            BadValue: "123 not a real number"
    "#;

    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;

    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };

    let string_query = AccessQuery::try_from(
        r#"Resources[ Type == 'AWS::EC2::SecurityGroup' ].Properties.SecurityGroupIngress.String"#,
    )?;

    let results = eval.query(&string_query.query)?;
    match results[0].clone() {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => {
            assert!(matches!(&*val, PathAwareValue::String(_)));
        }
        _ => unreachable!(),
    }

    let float = parse_float(&results)?;
    assert!(matches!(
        float[0].as_ref().unwrap(),
        PathAwareValue::Float(_)
    ));

    let float = parse_float(&results)?;
    assert!(matches!(
        float[0].as_ref().unwrap(),
        PathAwareValue::Float(_)
    ));

    let int_query = AccessQuery::try_from(
        r#"Resources[ Type == 'AWS::EC2::SecurityGroup' ].Properties.SecurityGroupIngress.Int"#,
    )?;
    let results = eval.query(&int_query.query)?;
    match results[0].clone() {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => {
            assert!(matches!(&*val, PathAwareValue::Int(_)));
        }
        _ => unreachable!(),
    }

    let float = parse_float(&results)?;
    assert!(matches!(
        float[0].as_ref().unwrap(),
        PathAwareValue::Float(_)
    ));

    let bad_value_query = AccessQuery::try_from(
        r#"Resources[ Type == 'AWS::EC2::SecurityGroup' ].Properties.SecurityGroupIngress.BadValue"#,
    )?;

    let results = eval.query(&bad_value_query.query)?;
    match results[0].clone() {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => {
            assert!(matches!(&*val, PathAwareValue::String(_)));
        }
        _ => unreachable!(),
    }

    let float = parse_int(&results);
    assert!(float.is_err());
    Ok(())
}

#[test]
fn test_parse_boolean() -> crate::rules::Result<()> {
    let value_str = r#"
    Resources:
      SecurityGroup:
        Type: AWS::EC2::SecurityGroup
        Properties:
          SecurityGroupIngress:
            String: "true"
            BadValue: "false fkdskljfl"
            Int: 0
    "#;

    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;

    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };

    let string_query = AccessQuery::try_from(
        r#"Resources[ Type == 'AWS::EC2::SecurityGroup' ].Properties.SecurityGroupIngress.String"#,
    )?;

    let results = eval.query(&string_query.query)?;
    match results[0].clone() {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => {
            assert!(matches!(&*val, PathAwareValue::String(_)));
        }
        _ => unreachable!(),
    }

    let bool = parse_boolean(&results)?;
    assert!(matches!(
        bool[0].as_ref().unwrap(),
        PathAwareValue::Bool((_, true))
    ));

    let int_query = AccessQuery::try_from(
        r#"Resources[ Type == 'AWS::EC2::SecurityGroup' ].Properties.SecurityGroupIngress.Int"#,
    )?;
    let results = eval.query(&int_query.query)?;
    match results[0].clone() {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => {
            assert!(matches!(&*val, PathAwareValue::Int(_)));
        }
        _ => unreachable!(),
    }

    let bool = parse_boolean(&results)?;
    assert!(bool[0].as_ref().is_none());

    let bad_value_query = AccessQuery::try_from(
        r#"Resources[ Type == 'AWS::EC2::SecurityGroup' ].Properties.SecurityGroupIngress.BadValue"#,
    )?;

    let results = eval.query(&bad_value_query.query)?;
    match results[0].clone() {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => {
            assert!(matches!(&*val, PathAwareValue::String(_)));
        }
        _ => unreachable!(),
    }

    let float = parse_int(&results);
    assert!(float.is_err());
    Ok(())
}

#[test]
fn test_parse_string() -> crate::rules::Result<()> {
    let value_str = r#"
    Resources:
      SecurityGroup:
        Type: AWS::EC2::SecurityGroup
        Properties:
          SecurityGroupIngress:
            String: "true"
            Int: 0
            Float: 1.0
            Bool: true
    "#;

    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;

    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };

    let string_query = AccessQuery::try_from(
        r#"Resources[ Type == 'AWS::EC2::SecurityGroup' ].Properties.SecurityGroupIngress.String"#,
    )?;

    let results = eval.query(&string_query.query)?;
    match results[0].clone() {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => {
            assert!(matches!(&*val, PathAwareValue::String(_)));
        }
        _ => unreachable!(),
    }

    let string = parse_string(&results)?;
    assert!(matches!(
        string[0].as_ref().unwrap(),
        PathAwareValue::String(_)
    ));

    let int_query = AccessQuery::try_from(
        r#"Resources[ Type == 'AWS::EC2::SecurityGroup' ].Properties.SecurityGroupIngress.Int"#,
    )?;
    let results = eval.query(&int_query.query)?;
    match results[0].clone() {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => {
            assert!(matches!(&*val, PathAwareValue::Int(_)));
        }
        _ => unreachable!(),
    }

    let string = parse_string(&results)?;
    assert!(matches!(
        string[0].as_ref().unwrap(),
        PathAwareValue::String(_)
    ));

    let string = parse_string(&results)?;
    assert!(matches!(
        string[0].as_ref().unwrap(),
        PathAwareValue::String(_)
    ));

    Ok(())
}
