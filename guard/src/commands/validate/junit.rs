use std::time::Duration;

pub struct TestSuite {
    pub name: String,
    pub test_cases: Vec<TestCase>,
}

#[]
pub struct TestCase {
    pub name: String,
    pub time: Duration,
    pub result: TestResult,
    pub file_path: Option<String>,
}

#[derive(Debug, Clone)]
pub enum TestResult {
    Success,
    Skipped,
    Failure,
}
