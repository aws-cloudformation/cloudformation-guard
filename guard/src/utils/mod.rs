#![allow(dead_code)]

pub mod reader;
pub mod writer;

/// The width in bytes of the line break at `bytes[at]`, or `None` if no break begins there.
///
/// This mirrors the definition libyaml uses rather than a summary of it, because a summary is what put
/// this function one line ending short twice over. The authority is
/// `unsafe-libyaml-0.2.11/src/macros.rs`:
///
/// ```text
/// macro_rules! IS_BREAK_AT {
///     CHECK_AT!($string, b'\r', $offset)
///         || CHECK_AT!($string, b'\n', $offset)
///         || CHECK_AT!($string, b'\xC2', $offset) && CHECK_AT!($string, b'\x85', $offset + 1)
///         || CHECK_AT!($string, b'\xE2', $offset) && ...b'\x80'... && ...b'\xA8'...
///         || CHECK_AT!($string, b'\xE2', $offset) && ...b'\x80'... && ...b'\xA9'...
/// }
/// ```
///
/// Five breaks: CR, LF, NEL `U+0085`, LS `U+2028`, PS `U+2029`, with CRLF as the CR-then-LF case. The
/// widths are `SKIP_LINE`'s, in `scanner.rs`: CRLF advances two bytes and counts one line, and every
/// other break advances its own UTF-8 width and counts one line. So the width returned here is the
/// number of bytes to step over, and each break is one line, which is what keeps this function's
/// numbering the same as the loader's.
///
/// The continuation bytes are load-bearing rather than defensive. `\xC2` also leads `U+00A0` no-break
/// space, and `\xE2\x80` leads `U+2026` ellipsis and twenty-odd other punctuation characters -- all
/// ordinary text that must not end a line. Testing the lead byte alone would split a line in the middle
/// of a character and hand `&buffer[start..at]` a boundary that is not a character boundary, which
/// panics.
///
/// Scanning byte by byte is safe here even though the buffer is UTF-8 text: no continuation byte can be
/// mistaken for the start of a break, because continuation bytes are `0x80..=0xBF` and every byte tested
/// above is either ASCII or a lead byte above `0xBF`.
fn break_width(bytes: &[u8], at: usize) -> Option<usize> {
    match bytes[at] {
        // CRLF is one ending, so step over both. Checked before the single-byte arm below.
        b'\r' if bytes.get(at + 1) == Some(&b'\n') => Some(2),
        b'\r' | b'\n' => Some(1),
        // NEL, `U+0085`.
        0xC2 if bytes.get(at + 1) == Some(&0x85) => Some(2),
        // LS `U+2028` and PS `U+2029`, which differ only in the last byte.
        0xE2 if bytes.get(at + 1) == Some(&0x80)
            && matches!(bytes.get(at + 2), Some(&0xA8) | Some(&0xA9)) =>
        {
            Some(3)
        }
        _ => None,
    }
}

/// The lines of `buffer`, ending at any of the five line breaks libyaml recognizes.
///
/// `str::lines` cannot be used here, and neither can a hand-written pair of `\r` and `\n` arms. Both
/// count fewer line endings than the loader that read the same file before this ever sees it, and the
/// two halves of one report then describe different files: `L:6` in the position and, beside it, an
/// excerpt whose lines are numbered against a different idea of what a line is.
///
/// `str::lines` splits on `\n` and strips a `\r` only when one precedes that `\n`, so a bare-CR file came
/// back as a single line. Fixing only that left three breaks still uncounted -- NEL, LS and PS -- and the
/// LS case is the one to keep in mind, because a lone `U+2028` in an otherwise-LF file is a routine
/// artifact of JavaScript tooling and its output looks plausible rather than broken. Measured on the
/// six-line template in `the_loader_and_the_read_cursor_agree_on_the_line_count`, the loader reported
/// `Encrypted[L:6,C:18]` while the excerpt labelled the same text `5.` and rendered two lines' worth of
/// it merged, the separator invisible. A reader given `L:6` and a line numbered 5 has no way to tell
/// which of the two is mistaken.
///
/// Everything `str::lines` gets right is kept: a terminator at the end of the file adds no empty line,
/// and a blank line in the middle is a line. Collapsing either renumbers the rest of the excerpt. The
/// trailing case is the one a naive extension gets wrong, because `start` has to clear *every* byte of
/// the terminator -- step one byte past a three-byte LS and `start` lands on `\x80`, and the file grows
/// a final line made of the tail of a separator.
///
/// Eager rather than an iterator, because the result is a `Vec` of slices into a buffer that is already
/// in memory, and `ReadCursor` caches every line it reads anyway.
fn split_lines(buffer: &str) -> Vec<&str> {
    let bytes = buffer.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0;
    let mut at = 0;

    while at < bytes.len() {
        match break_width(bytes, at) {
            Some(width) => {
                lines.push(&buffer[start..at]);
                at += width;
                start = at;
            }
            None => at += 1,
        }
    }

    // Text after the last terminator is a line; a file ending in one has nothing after it.
    if start < bytes.len() {
        lines.push(&buffer[start..]);
    }

    lines
}

#[derive(Debug, Clone)]
pub(crate) struct ReadCursor<'buffer> {
    line_num: usize,
    line_buffer: std::vec::IntoIter<&'buffer str>,
    previous_lines: Vec<(usize, &'buffer str)>,
}

impl<'buffer> ReadCursor<'buffer> {
    pub(crate) fn new(buffer: &str) -> ReadCursor {
        ReadCursor {
            line_num: 0,
            line_buffer: split_lines(buffer).into_iter(),
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

    /// The five line breaks libyaml recognizes, each with the bytes it is.
    ///
    /// The bytes are here so that `separator_bytes_are_what_they_claim` can hold every case below to
    /// them. A fixture that means to hold `U+2028` and holds a plain space instead still produces a
    /// mismatch against the loader, so a test that only compared line numbers would go green on a
    /// document that never contained the character it names -- and would go on passing after the
    /// separator it was written for stopped being handled.
    const BREAKS: [(&str, &str, &[u8]); 6] = [
        ("LF", "\n", &[0x0A]),
        ("CRLF", "\r\n", &[0x0D, 0x0A]),
        ("bare CR", "\r", &[0x0D]),
        ("NEL U+0085", "\u{0085}", &[0xC2, 0x85]),
        ("LS U+2028", "\u{2028}", &[0xE2, 0x80, 0xA8]),
        ("PS U+2029", "\u{2029}", &[0xE2, 0x80, 0xA9]),
    ];

    /// The control for every case in this module: each separator is the bytes it claims to be.
    ///
    /// Without this, a mistyped fixture reads as a different defect. That is not hypothetical -- a
    /// six-line template built to demonstrate the `U+2028` case was first written joining its lines with
    /// a plain space, and it reported a line-number mismatch too, for an unrelated reason.
    #[test]
    fn separator_bytes_are_what_they_claim() {
        for (spelling, separator, bytes) in BREAKS {
            assert_eq!(
                bytes,
                separator.as_bytes(),
                "{} is not the bytes it claims to be",
                spelling
            );
        }
    }

    /// A line ends at any of the five breaks libyaml recognizes, which is what the loader beside this
    /// already counts.
    ///
    /// This cursor fed `str::lines`, which splits on `\n` and strips a `\r` only when one precedes that
    /// `\n`. So a data file whose lines end with a bare `\r` was **one line**. libyaml does not agree
    /// with that -- a lone CR is a line break in YAML, and the loader counts it -- so the two halves of
    /// one report described different files. Measured on a six-line template with `Encrypted: false` on
    /// line 6, whose only difference from its LF twin was the line endings:
    ///
    /// ```text
    /// LF        PropertyPath = /Resources/One/Properties/Encrypted[L:6,C:18]
    ///           Code:      4.    Properties:
    ///                      5.      Tags: []
    ///                      6.      Encrypted: false
    ///
    /// bare CR   PropertyPath = /Resources/One/Properties/Encrypted[L:6,C:18]      <- still right
    ///           Code:      1.Resources:\r  One:\r    Type: ...\r      Encrypted: false\r
    /// ```
    ///
    /// The position was never wrong; the excerpt beside it was the whole file labelled line 1, control
    /// characters included. A reader given `L:6` and one line of text has no way to tell which of the
    /// two is mistaken.
    ///
    /// Repairing CR alone left three breaks still uncounted, and they fail the same way: with a uniform
    /// NEL, LS or PS file the excerpt was the whole file labelled `1.`, and with a single one of them in
    /// an otherwise-LF file the excerpt's last line was numbered `5.` against a reported `L:6`. The
    /// three-byte pair is the worst case in practice, because a lone `U+2028` is a routine artifact of
    /// JavaScript tooling and the output it produces looks plausible rather than broken.
    ///
    /// The mixed case is a judgement rather than a repair: a lone `\r` inside an otherwise-LF file now
    /// ends a line, where `str::lines` would have kept `two\rthree` together. That is the judgement
    /// libyaml makes when it counts those lines, and the one the rules parser makes, and this cursor
    /// exists to index text libyaml has already read.
    #[test]
    fn read_cursor_ends_a_line_at_every_libyaml_line_break() {
        // A function rather than a closure: a closure taking `&str` and returning slices of it cannot
        // express that the two lifetimes are the same one, and rustc rejects it.
        fn read_all(buffer: &str) -> Vec<(usize, &str)> {
            let mut cursor = ReadCursor::new(buffer);
            let mut read = Vec::new();
            while let Some(line) = cursor.next() {
                read.push(line);
            }
            read
        }

        for (spelling, separator, _) in BREAKS {
            // Three lines, however the two separators between them are spelled.
            let buffer = format!("one{sep}two{sep}three", sep = separator);
            assert_eq!(
                vec![(1, "one"), (2, "two"), (3, "three")],
                read_all(&buffer),
                "every spelling of a line ending has to give the same three lines, and this one is \
                 {}: {:?}",
                spelling,
                buffer
            );

            // A terminator at the end of the file adds no empty line. This is the case a naive
            // extension gets wrong for a multi-byte separator: clearing only the lead byte leaves
            // `start` inside the separator and the file grows a final line made of its tail.
            let trailing = format!("one{sep}two{sep}three{sep}", sep = separator);
            assert_eq!(
                vec![(1, "one"), (2, "two"), (3, "three")],
                read_all(&trailing),
                "a final {} adds no fourth line: {:?}",
                spelling,
                trailing
            );

            // An empty line in the middle is a line, in every spelling. `str::lines` keeps it too, and
            // a replacement that collapsed it would renumber every line after it in the excerpt.
            let blank = format!("one{sep}{sep}three", sep = separator);
            assert_eq!(
                vec![(1, "one"), (2, ""), (3, "three")],
                read_all(&blank),
                "the blank line is line 2, separated by {}: {:?}",
                spelling,
                blank
            );
        }

        // Mixed separators, which is what a botched conversion leaves. Every pair is exercised so that
        // no ordering of two breaks is handled only by accident -- in particular CR before LF, which
        // must stay one break rather than becoming two.
        for (_, first, _) in BREAKS {
            for (_, second, _) in BREAKS {
                let buffer = format!("one{first}two{second}three");
                assert_eq!(
                    vec![(1, "one"), (2, "two"), (3, "three")],
                    read_all(&buffer),
                    "mixed separators still give three lines: {:?}",
                    buffer
                );
            }
        }

        // No text, no lines -- `seek_line` on an empty file answers None rather than indexing into
        // nothing.
        let mut empty = ReadCursor::new("");
        assert_eq!(None, empty.next());
        assert_eq!(None, ReadCursor::new("").seek_line(1));
    }

    /// A lead byte without its continuation bytes is ordinary text, not a line break.
    ///
    /// `\xC2` leads `U+0085` NEL and also `U+00A0` no-break space; `\xE2\x80` leads `U+2028` and
    /// `U+2029` and also `U+2026` ellipsis, `U+201C` quotation marks and twenty-odd other punctuation
    /// characters that appear in ordinary template text. Matching on the lead byte alone would split a
    /// line in the middle of a character, and slicing the buffer at a boundary that is not a character
    /// boundary panics -- so this is the difference between a wrong line number and a crash.
    #[test]
    fn a_lead_byte_without_its_continuation_is_not_a_break() {
        for (name, text) in [
            ("U+00A0 no-break space", "one\u{00A0}two"),
            ("U+00A1 inverted exclamation", "one\u{00A1}two"),
            ("U+2026 ellipsis", "one\u{2026}two"),
            ("U+201C left quotation mark", "one\u{201C}two"),
            ("U+2027 hyphenation point, just below LS", "one\u{2027}two"),
            ("U+202A embedding, just above PS", "one\u{202A}two"),
        ] {
            let mut cursor = ReadCursor::new(text);
            let first = cursor.next();
            assert_eq!(
                Some((1, text)),
                first,
                "{} is text, so the whole buffer is one line",
                name
            );
            assert_eq!(None, cursor.next(), "and there is no second line: {}", name);
        }
    }
}
