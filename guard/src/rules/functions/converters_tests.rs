use std::{convert::TryFrom, rc::Rc};

use crate::rules::{
    eval_context::eval_context_tests::BasicQueryTesting,
    exprs::AccessQuery,
    functions::converters::{parse_bool, parse_char, parse_float, parse_int, parse_str},
    path_value::{Path, PathAwareValue},
    EvalContext, QueryResult,
};

/// One value in, one answer out, for a converter that takes a single argument.
fn convert_one(
    f: fn(&[QueryResult]) -> crate::rules::Result<Vec<Option<PathAwareValue>>>,
    value: PathAwareValue,
) -> crate::rules::Result<Vec<Option<PathAwareValue>>> {
    f(&[QueryResult::Resolved(Rc::new(value))])
}

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

    let bool = parse_bool(&results)?;
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

    let bool = parse_bool(&results)?;
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

    let string = parse_str(&results)?;
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

    let string = parse_str(&results)?;
    assert!(matches!(
        string[0].as_ref().unwrap(),
        PathAwareValue::String(_)
    ));

    let string = parse_str(&results)?;
    assert!(matches!(
        string[0].as_ref().unwrap(),
        PathAwareValue::String(_)
    ));

    Ok(())
}

#[test]
fn test_parse_char() -> crate::rules::Result<()> {
    let value_str = r#"
{
    "Resources": {
        "SecurityGroup": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "SecurityGroupIngress": {
                    "String": "1",
                    "Int": 1,
                    "Char": '1',
                    "BadValue": "123"
                }
            }
        }
    }
}
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

    let integer = parse_char(&results)?;
    assert!(matches!(
        integer[0].as_ref().unwrap(),
        PathAwareValue::Char((_, '1'))
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

    let integer = parse_char(&results)?;
    assert!(matches!(
        integer[0].as_ref().unwrap(),
        PathAwareValue::Char((_, '1'))
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

    let integer = parse_char(&results)?;
    assert!(matches!(
        integer[0].as_ref().unwrap(),
        PathAwareValue::Char((_, '1'))
    ));

    let bad_query = AccessQuery::try_from(
        r#"Resources[ Type == 'AWS::EC2::SecurityGroup' ].Properties.SecurityGroupIngress.BadValue"#,
    )?;

    let results = eval.query(&bad_query.query)?;
    match results[0].clone() {
        QueryResult::Literal(val) | QueryResult::Resolved(val) => {
            assert!(matches!(&*val, PathAwareValue::String(_)));
        }
        _ => unreachable!(),
    }

    assert!(parse_char(&results).is_err());

    Ok(())
}

/// `parse_int` refuses a float that does not fit in an `i64` rather than clamping it to the nearest end.
///
/// `*val as i64` saturates in Rust, and nothing reported that it had. `1.0e30` and `1.0e40` differ by ten
/// orders of magnitude and both came back as 9223372036854775807, so a rule asserting the two are equal
/// passed and a rule asserting they differ failed. The passing direction is the damaging one: two numbers
/// that do not match were reported as matching, at exit 0.
///
/// Truncation toward zero stays, because `docs/FUNCTIONS.md:362` promises it -- what it does not promise
/// is that a value too large to represent becomes `i64::MAX`. The same document says the conversion errors
/// on input it cannot convert, and a value that does not fit is exactly that.
///
/// The two bounds are not symmetric, and the boundary rows are here to pin it. `-2^63` is exactly
/// representable as an `f64`, so the low end is inclusive. `i64::MAX` is `2^63 - 1`, which is *not*
/// representable, so `i64::MAX as f64` rounds up to `2^63` and the high end has to be exclusive. Getting
/// that backwards would let `2^63` through to saturate again.
#[test]
fn parse_int_does_not_saturate_a_float_that_does_not_fit() -> crate::rules::Result<()> {
    // The largest f64 below 2^63. Values in [2^62, 2^63) step by 1024, so this is 2^63 - 1024.
    const LARGEST_BELOW_2_POW_63: f64 = 9223372036854774784.0;

    let allowed: [(f64, i64); 7] = [
        // Truncation toward zero, which is the documented behaviour.
        (5.0, 5),
        (1.9, 1),
        (-1.9, -1),
        (0.0, 0),
        (-0.5, 0),
        // Both ends of the representable range.
        (LARGEST_BELOW_2_POW_63, 9223372036854774784),
        (-9223372036854775808.0, i64::MIN),
    ];

    for (input, expected) in allowed {
        match convert_one(parse_int, PathAwareValue::Float((Path::root(), input)))?
            .first()
            .cloned()
            .flatten()
        {
            Some(PathAwareValue::Int((_, got))) => {
                assert_eq!(got, expected, "parse_int({:?})", input)
            }
            other => panic!(
                "parse_int({:?}) gave {:?}, expected {:?}",
                input, other, expected
            ),
        }
    }

    let refused: [f64; 7] = [
        1.0e30,
        1.0e40,
        -1.0e40,
        // 2^63 itself, one step past the top of the range. This is what `i64::MAX as f64` rounds to.
        9223372036854775808.0,
        // The first f64 below -2^63. Not -2^63-1: that is not representable and rounds back to -2^63,
        // which is in range, so it is no test of anything. Magnitudes in [2^63, 2^64) step by 2048.
        -9223372036854777856.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ];

    for input in refused {
        let outcome = convert_one(parse_int, PathAwareValue::Float((Path::root(), input)));
        match outcome {
            Err(crate::Error::IncompatibleError(message)) => assert!(
                message.contains("does not fit"),
                "parse_int({:?}) should say the value does not fit; got {:?}",
                input,
                message
            ),
            other => panic!("parse_int({:?}) should be refused; got {:?}", input, other),
        }
    }

    // NaN cast to i64 was 0, which is a number the input never denoted.
    match convert_one(parse_int, PathAwareValue::Float((Path::root(), f64::NAN))) {
        Err(crate::Error::IncompatibleError(_)) => {}
        other => panic!("parse_int(NaN) should be refused; got {:?}", other),
    }

    Ok(())
}

/// `parse_float` refuses a numeric literal too large to represent rather than answering infinity.
///
/// `val.parse::<f64>()` returns `Ok(inf)` for an overflowing literal rather than `Err`, so `"1e400"` and
/// `"9e999"` both became `inf` and compared equal. Same shape as the `parse_int` saturation above, and the
/// same passing direction: a rule asserting the two are equal is satisfied.
///
/// `"NaN"` and `"inf"` spelled out in the data are refused too. Their verdict does not change -- a NaN
/// already failed every comparison it reached, with `[Float values are not comparable]` -- but the
/// diagnostic now names the property instead of surfacing as a comparison failure further down. A value
/// that cannot take part in a comparison is not a float a rule can use.
#[test]
fn parse_float_does_not_turn_an_overflowing_literal_into_infinity() -> crate::rules::Result<()> {
    let allowed: [(&str, f64); 5] = [
        ("2.5", 2.5),
        ("-2.5", -2.5),
        ("0", 0.0),
        ("2456", 2456.0),
        // Close to the top of the f64 range and still finite.
        ("1e308", 1e308),
    ];

    for (input, expected) in allowed {
        match convert_one(
            parse_float,
            PathAwareValue::String((Path::root(), String::from(input))),
        )?
        .first()
        .cloned()
        .flatten()
        {
            Some(PathAwareValue::Float((_, got))) => {
                assert_eq!(got, expected, "parse_float({:?})", input)
            }
            other => panic!(
                "parse_float({:?}) gave {:?}, expected {:?}",
                input, other, expected
            ),
        }
    }

    // Overflowing literals, and the two non-finite spellings.
    for input in ["1e400", "9e999", "-1e400", "NaN", "nan", "inf", "-inf"] {
        let outcome = convert_one(
            parse_float,
            PathAwareValue::String((Path::root(), String::from(input))),
        );
        match outcome {
            Err(crate::Error::IncompatibleError(_)) => {}
            other => panic!(
                "parse_float({:?}) should be refused; got {:?}",
                input, other
            ),
        }
    }

    Ok(())
}

/// `parse_char` accepts a single character that is not ASCII.
///
/// The length guard was `val.len() > 1`, and `String::len()` counts bytes, so `"é"` -- one character, two
/// bytes -- was refused as too long, and so was any emoji. The line immediately after it already read the
/// value with `val.chars().next()`, so the function extracted by character and only its guard was in
/// bytes. `substring` carries a comment about having fixed exactly this confusion; the fix was applied
/// there and not here.
///
/// It fails closed, so this is a wrong rejection rather than a wrong pass, and the message compounded it
/// by reporting a failed conversion when what happened is that the test used the wrong unit.
///
/// Characters here means Unicode scalar values, which is what `chars()` yields and what `substring`
/// already indexes by. An `e` followed by a combining acute accent is two of those and is still refused,
/// even though it draws as one glyph -- the two functions agree, which matters more than either answer.
#[test]
fn parse_char_measures_length_in_characters_not_bytes() -> crate::rules::Result<()> {
    // (input, expected character, how many bytes it occupies)
    let accepted: [(&str, char, usize); 5] = [
        ("a", 'a', 1),
        // Two bytes. This is the rejection.
        ("é", 'é', 2),
        // Three bytes.
        ("日", '日', 3),
        // Four bytes.
        ("😀", '😀', 4),
        ("7", '7', 1),
    ];

    for (input, expected, bytes) in accepted {
        assert_eq!(input.len(), bytes, "{:?} should be {} bytes", input, bytes);
        assert_eq!(input.chars().count(), 1, "{:?} should be one char", input);

        match convert_one(
            parse_char,
            PathAwareValue::String((Path::root(), String::from(input))),
        )?
        .first()
        .cloned()
        .flatten()
        {
            Some(PathAwareValue::Char((_, got))) => {
                assert_eq!(got, expected, "parse_char({:?})", input)
            }
            other => panic!(
                "parse_char({:?}) gave {:?}, expected the char {:?}",
                input, other, expected
            ),
        }
    }

    // More than one character is still refused, whatever the byte count.
    for input in ["ab", "aé", "éé", "e\u{0301}"] {
        assert!(
            input.chars().count() > 1,
            "{:?} is supposed to be several characters",
            input
        );
        match convert_one(
            parse_char,
            PathAwareValue::String((Path::root(), String::from(input))),
        ) {
            Err(crate::Error::IncompatibleError(_)) => {}
            other => panic!("parse_char({:?}) should be refused; got {:?}", input, other),
        }
    }

    // The empty string keeps answering with no value rather than erroring, as it did before.
    match convert_one(
        parse_char,
        PathAwareValue::String((Path::root(), String::new())),
    )?
    .first()
    {
        Some(None) => {}
        other => panic!("parse_char(\"\") should yield no value; got {:?}", other),
    }

    Ok(())
}
