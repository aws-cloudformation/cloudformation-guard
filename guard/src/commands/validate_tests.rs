use crate::commands::validate;
use crate::command::Command;

#[test]
fn test_deserialize_payload_success() {
    let serialized_payload = "{\"data\":[\"data as string 1\",\"data as string 2\"], \"rules\":[\"rules as string 1\",\"rules as string 2\"]}";
    let deserialized_payload = validate::deserialize_payload(serialized_payload).unwrap();
    assert_eq!(deserialized_payload.list_of_data, vec!["data as string 1", "data as string 2"]);
    assert_eq!(deserialized_payload.list_of_rules, vec!["rules as string 1", "rules as string 2"]);
}

#[test]
#[should_panic]
fn test_deserialize_payload_bad_input1() {
    let serialized_payload = "{\"data:[\"data as string 1\",\"data as string 2\"], \"rules\":[\"rules as string 1\",\"rules as string 2\"]}";
    validate::deserialize_payload(serialized_payload).unwrap();
}

#[test]
#[should_panic]
fn test_deserialize_payload_bad_input2() {
    let serialized_payload = "{\"data\":[\"data as string 1\",\"data as string 2\"], \"wrongProperty\":\"wrongProperty\"}";
    validate::deserialize_payload(serialized_payload).unwrap();
}

#[test]
#[should_panic]
fn test_deserialize_payload_empty_input() {
    let serialized_payload = "";
    validate::deserialize_payload(serialized_payload).unwrap();
}