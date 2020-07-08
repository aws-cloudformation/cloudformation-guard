// © Amazon Web Services, Inc. or its affiliates. All Rights Reserved. This AWS Content is provided subject to the terms of the AWS Customer Agreement available at http://aws.amazon.com/agreement or other written agreement between Customer and either Amazon Web Services, Inc. or Amazon Web Services EMEA SARL or both.
// Structs, Enums and Impls

pub mod enums {
    #[derive(Debug, PartialEq)]
    pub enum LineType {
        Assignment,
        Comment,
        Conditional,
        Rule,
        WhiteSpace,
    }

    #[derive(Debug, Hash, PartialEq, Eq, Clone)]
    pub enum OpCode {
        Require,
        RequireNot,
        In,
        NotIn,
        LessThan,
        LessThanOrEqualTo,
        GreaterThan,
        GreaterThanOrEqualTo,
    }

    #[derive(Debug, Hash, PartialEq, Eq, Clone)]
    pub enum RValueType {
        Value,
        List,
        Regex,
        Variable,
    }
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub enum CompoundType {
        OR,
        AND,
    }

    #[derive(Debug, Clone)]
    pub enum RuleType {
        CompoundRule(super::structs::CompoundRule),
        ConditionalRule(super::structs::ConditionalRule),
    }
}

pub mod structs {
    use std::collections::HashMap;

    #[derive(Debug, Hash, Eq, PartialEq, Clone)]
    pub struct Rule {
        pub(crate) resource_type: String,
        pub(crate) field: String,
        pub(crate) operation: super::enums::OpCode,
        pub(crate) value: String,
        pub(crate) rule_vtype: super::enums::RValueType,
        pub(crate) custom_msg: Option<String>,
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct CompoundRule {
        pub(crate) compound_type: super::enums::CompoundType,
        pub(crate) raw_rule: String,
        pub(crate) rule_list: Vec<Rule>,
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct ConditionalRule {
        pub(crate) condition: CompoundRule,
        pub(crate) consequent: CompoundRule,
    }

    #[derive(Debug)]
    pub struct ParsedRuleSet {
        pub(crate) variables: HashMap<String, String>,
        pub(crate) rule_set: Vec<super::enums::RuleType>,
    }
}
