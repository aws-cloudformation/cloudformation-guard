use std::rc::Rc;

#[derive(Debug, Clone)]
pub(crate) struct ReadCursor<'buffer> {
    line_num: usize,
    line_buffer: std::str::Lines<'buffer>,
    previous_lines: Vec<(usize, &'buffer str)>
}

impl<'buffer> ReadCursor<'buffer> {
    pub(crate) fn new<'b>(buffer: &'b str) -> ReadCursor<'b> {
        ReadCursor {
            line_num: 0,
            line_buffer: buffer.lines(),
            previous_lines: Default::default(),
        }
    }

    pub(crate) fn next(&mut self) -> Option<(usize, &'buffer str)> {
        if self.line_num < self.previous_lines.len() {
            self.line_num += 1;
            return Some(self.previous_lines[self.line_num-1].clone())
        }
        match self.line_buffer.next() {
            Some(line) => {
                self.line_num += 1;
                self.previous_lines.push((self.line_num, line));
                return Some(self.previous_lines[self.line_num-1].clone())
            },
            None => None
        }
    }

    pub(crate) fn prev(&mut self) -> Option<(usize, &'buffer str)> {
        if self.line_num - 1 > 0 && self.previous_lines.len() > 0 {
            self.line_num -= 1;
            return Some(self.previous_lines[self.line_num].clone())
        }
        None
    }

    pub(crate) fn seek_line(&mut self, line: usize) -> Option<(usize, &'buffer str)> {
        if self.previous_lines.len() > line {
            self.line_num = line;
            return Some(self.previous_lines[self.line_num-1].clone())
        }

        loop {
            match self.line_buffer.next() {
                Some(l) => {
                    self.line_num += 1;
                    self.previous_lines.push((self.line_num, l));
                    if self.line_num == line {
                        return Some(self.previous_lines[self.line_num-1].clone())
                    }
                },
                None => return None
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
        let mut line = 0;
        while let Some(line) = cursor.next() {
            println!("{}.{}", line.0, line.1);
        }
        let prev = cursor.prev();
        assert_eq!(prev.is_some(), true);
        let prev = match prev { Some(p) => p, None => unreachable!() };
        assert_eq!(prev.1.contains("${s3}"), true);
        let _ = cursor.next();
        let mut lines = Vec::with_capacity(cursor.previous_lines.len());
        while let Some((line, prev)) = cursor.prev() {
            lines.insert(0, (line, prev));
            if prev.contains("s3Policy:") {
                break
            }
        }
        for each in lines {
            println!("{}.{}", each.0, each.1);
        }
    }
}