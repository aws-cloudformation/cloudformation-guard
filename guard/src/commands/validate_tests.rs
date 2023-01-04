use super::super::*;
use super::*;

#[test]
fn test_deserialize_payload_success() {
    let serialized_payload = "{\"data\":[\"data as string 1\",\"data as string 2\"], \"rules\":[\"rules as string 1\",\"rules as string 2\"]}";
    let deserialized_payload = validate::deserialize_payload(serialized_payload).unwrap();
    assert_eq!(deserialized_payload.list_of_data, vec!["data as string 1", "data as string 2"]);
    assert_eq!(deserialized_payload.list_of_rules, vec!["rules as string 1", "rules as string 2"]);
}

#[test]
#[should_panic]
fn test_deserialize_payload_malformed_string() {
    let serialized_payload = "{\"data:[\"data as string 1\",\"data as string 2\"], \"rules\":[\"rules as string 1\",\"rules as string 2\"]}";
    validate::deserialize_payload(serialized_payload).unwrap();
}

#[test]
#[should_panic]
fn test_deserialize_payload_unrecognized_property() {
    let serialized_payload = "{\"data\":[\"data as string 1\",\"data as string 2\"], \"wrongProperty\":\"wrongProperty\"}";
    validate::deserialize_payload(serialized_payload).unwrap();
}

#[test]
#[should_panic]
fn test_deserialize_payload_empty_input() {
    let serialized_payload = "";
    validate::deserialize_payload(serialized_payload).unwrap();
}


#[test]
fn test_supported_extensions() {
    // Data extensions
    assert!(has_a_supported_extension(&"blah.json".to_string(), &DATA_FILE_SUPPORTED_EXTENSIONS));
    assert!(has_a_supported_extension(&"blah.jsn".to_string(), &DATA_FILE_SUPPORTED_EXTENSIONS));
    assert!(has_a_supported_extension(&"blah.yaml".to_string(), &DATA_FILE_SUPPORTED_EXTENSIONS));
    assert!(has_a_supported_extension(&"blah.template".to_string(), &DATA_FILE_SUPPORTED_EXTENSIONS));
    assert!(has_a_supported_extension(&"blah.yml".to_string(), &DATA_FILE_SUPPORTED_EXTENSIONS));
    // unsupported
    assert!(!has_a_supported_extension(&"blah.txt".to_string(), &DATA_FILE_SUPPORTED_EXTENSIONS));
    assert!(!has_a_supported_extension(&"blah".to_string(), &DATA_FILE_SUPPORTED_EXTENSIONS));

    // Rules extensions
    assert!(has_a_supported_extension(&"blah.guard".to_string(), &RULE_FILE_SUPPORTED_EXTENSIONS));
    assert!(has_a_supported_extension(&"blah.ruleset".to_string(), &RULE_FILE_SUPPORTED_EXTENSIONS));
    // unsupported
    assert!(!has_a_supported_extension(&"blah.txt".to_string(), &RULE_FILE_SUPPORTED_EXTENSIONS));
    assert!(!has_a_supported_extension(&"blah".to_string(), &RULE_FILE_SUPPORTED_EXTENSIONS));
}