#![allow(dead_code)]
use crate::{command::Command, commands};

pub mod reader;
pub mod writer;

#[derive(Debug, Clone)]
pub(crate) struct ReadCursor<'buffer> {
    line_num: usize,
    line_buffer: std::str::Lines<'buffer>,
    previous_lines: Vec<(usize, &'buffer str)>,
}

pub fn get_guard_commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(commands::parse_tree::ParseTree::new()),
        Box::new(commands::test::Test::new()),
        Box::new(commands::validate::Validate::new()),
        Box::new(commands::rulegen::Rulegen::new()),
    ]
}

impl<'buffer> ReadCursor<'buffer> {
    pub(crate) fn new(buffer: &str) -> ReadCursor {
        ReadCursor {
            line_num: 0,
            line_buffer: buffer.lines(),
            previous_lines: Default::default(),
        }
    }

    pub(crate) fn next(&mut self) -> Option<(usize, &'buffer str)> {
        if self.line_num < self.previous_lines.len() {
            self.line_num += 1;
            return Some(self.previous_lines[self.line_num - 1]);
        }
        match self.line_buffer.next() {
            Some(line) => {
                self.line_num += 1;
                self.previous_lines.push((self.line_num, line));
                Some(self.previous_lines[self.line_num - 1])
            }
            None => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn prev(&mut self) -> Option<(usize, &'buffer str)> {
        if self.line_num - 1 > 0 && !self.previous_lines.is_empty() {
            self.line_num -= 1;
            return Some(self.previous_lines[self.line_num]);
        }
        None
    }

    pub(crate) fn seek_line(&mut self, line: usize) -> Option<(usize, &'buffer str)> {
        if self.previous_lines.len() > line {
            self.line_num = line;
            return Some(self.previous_lines[self.line_num - 1]);
        }

        loop {
            match self.line_buffer.next() {
                Some(l) => {
                    self.line_num += 1;
                    self.previous_lines.push((self.line_num, l));
                    if self.line_num == line {
                        return Some(self.previous_lines[self.line_num - 1]);
                    }
                }
                None => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_cursor_test() {
        let resources = r###"
    Resources:
      s3:
        Type: AWS::S3::Bucket
      s3Policy:
        Type: AWS::S3::BucketPolicy
        Properties:
          PolicyDocument:
            Statement:
              Resource:
                Fn::Sub: "aws:arn:s3::${s3}""###;

        let mut cursor = ReadCursor::new(resources);
        while let Some(line) = cursor.next() {
            println!("{}.{}", line.0, line.1);
        }
        let prev = cursor.prev();
        assert!(prev.is_some());
        let prev = match prev {
            Some(p) => p,
            None => unreachable!(),
        };
        assert!(prev.1.contains("${s3}"));
        let _ = cursor.next();
        let mut lines = Vec::with_capacity(cursor.previous_lines.len());
        while let Some((line, prev)) = cursor.prev() {
            lines.insert(0, (line, prev));
            if prev.contains("s3Policy:") {
                break;
            }
        }
        for each in lines {
            println!("{}.{}", each.0, each.1);
        }
    }
}
