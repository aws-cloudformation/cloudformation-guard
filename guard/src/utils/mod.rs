#![allow(dead_code)]

pub mod reader;
pub mod writer;

#[derive(Debug, Clone)]
pub(crate) struct ReadCursor<'buffer> {
    line_num: usize,
    line_buffer: std::str::Lines<'buffer>,
    previous_lines: Vec<(usize, &'buffer str)>,
}

impl<'buffer> ReadCursor<'buffer> {
    pub(crate) fn new(buffer: &str) -> ReadCursor<'_> {
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

    /// Rewind or advance to `line`, 1-based, returning that line.
    ///
    /// `line == 0` is not a line, and the cache lookup below would underflow on it. Answering
    /// `None` here rather than relying on callers to clamp: `cfn::context_start_line` does clamp,
    /// and this function should not be correct only because of that.
    ///
    /// Fills the cache up to `line`, then answers from it. The previous version drove the read
    /// loop off `self.line_num`, which is a cursor and can point behind the cache after a rewind,
    /// and that produced two separate defects:
    ///
    /// - The cache was only consulted when `previous_lines.len() > line`, so a request for exactly
    ///   the highest line already read fell through to the loop, which compares each newly pulled
    ///   line against a number it has already passed. It drained to EOF and answered `None`.
    ///   `emit_code` shares one cursor across every violation in a file and reads six lines per
    ///   violation -- one at the seek point and five after -- so two violations exactly five lines
    ///   apart put the second one's context start on that boundary and its whole `Code:` snippet
    ///   rendered blank.
    /// - Pulling inside that loop labelled each new line with the rewound `line_num` rather than
    ///   its real position, so `previous_lines` ended up holding duplicate and wrong line numbers
    ///   and every later lookup was off. `next` and `prev` both index `previous_lines` positionally
    ///   and so depend on that invariant holding.
    ///
    /// Deriving the number from the cache length keeps `previous_lines[i] == (i + 1, ..)` true by
    /// construction, which is the invariant the rest of the type was already assuming. Pinned by
    /// `seek_line_returns_a_cached_line_at_the_read_boundary`.
    pub(crate) fn seek_line(&mut self, line: usize) -> Option<(usize, &'buffer str)> {
        if line == 0 {
            return None;
        }

        while self.previous_lines.len() < line {
            match self.line_buffer.next() {
                Some(l) => {
                    let num = self.previous_lines.len() + 1;
                    self.previous_lines.push((num, l));
                }
                None => return None,
            }
        }

        self.line_num = line;
        Some(self.previous_lines[line - 1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_cursor_test() {
        let resources = r#"
    Resources:
      s3:
        Type: AWS::S3::Bucket
      s3Policy:
        Type: AWS::S3::BucketPolicy
        Properties:
          PolicyDocument:
            Statement:
              Resource:
                Fn::Sub: "aws:arn:s3::${s3}""#;

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

    /// Seeking to the highest line already read must return it, not drain the iterator.
    ///
    /// The cache guard was `previous_lines.len() > line`, so a request for exactly the boundary
    /// line fell through to the loop. The loop only pulls *new* lines and tests each against
    /// `line`, which it has already passed, so it ran to EOF and answered `None`.
    ///
    /// The caller this matters for is `cfn::single_line`'s `emit_code`, which shares one cursor
    /// across every violation in a file and reads six lines per violation -- one at the seek point
    /// and five after. So the boundary is hit whenever two violations are exactly five lines
    /// apart, and the second one's whole `Code:` snippet came out blank. The last two assertions
    /// are that case end to end: seek, read five, seek to where the reading stopped.
    #[test]
    fn seek_line_returns_a_cached_line_at_the_read_boundary() {
        let buffer = "one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten";

        let mut cursor = ReadCursor::new(buffer);
        assert_eq!(Some((3, "three")), cursor.seek_line(3));
        // previous_lines now holds exactly three lines, so 3 is the boundary.
        assert_eq!(Some((3, "three")), cursor.seek_line(3));
        // Below the boundary still works, which is all the old guard covered.
        assert_eq!(Some((1, "one")), cursor.seek_line(1));
        // Beyond it still reads forward.
        assert_eq!(Some((7, "seven")), cursor.seek_line(7));

        // Line numbers are 1-based, so 0 is not a line. The old code indexed
        // `previous_lines[line - 1]` and underflowed.
        assert_eq!(None, cursor.seek_line(0));

        // The `emit_code` shape: seek, read five, then seek to the line reading stopped on.
        let mut cursor = ReadCursor::new(buffer);
        assert_eq!(Some((3, "three")), cursor.seek_line(3));
        for _ in 0..5 {
            assert!(cursor.next().is_some());
        }
        assert_eq!(
            Some((8, "eight")),
            cursor.seek_line(8),
            "a second violation five lines below the first asked for the line reading had just \
             stopped on, and got None -- which renders as an empty Code: block"
        );
    }
}
