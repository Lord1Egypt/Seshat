//! Source normalization — a faithful port of `seshat.normalize`.
//!
//! Strips comments and string/char literals while **preserving newlines** so
//! line numbers stay identical to the Python engine. Same state machine as
//! `strip_comments_and_strings` in Python. Iterates over chars (UTF-8 safe).

#[derive(PartialEq)]
enum State {
    Code,
    LineComment,
    BlockComment,
    StringLit,
}

/// Blank out comments and string/char literals, preserving every newline.
pub fn strip_comments_and_strings(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    let mut state = State::Code;
    let mut quote = ' ';

    while i < n {
        let c = chars[i];
        let nxt = if i + 1 < n { chars[i + 1] } else { '\0' };
        match state {
            State::Code => {
                if c == '/' && nxt == '/' {
                    state = State::LineComment;
                    out.push_str("  ");
                    i += 2;
                } else if c == '/' && nxt == '*' {
                    state = State::BlockComment;
                    out.push_str("  ");
                    i += 2;
                } else if c == '"' || c == '\'' {
                    state = State::StringLit;
                    quote = c;
                    out.push(' ');
                    i += 1;
                } else {
                    out.push(c);
                    i += 1;
                }
            }
            State::LineComment => {
                if c == '\n' {
                    state = State::Code;
                    out.push('\n');
                } else {
                    out.push(' ');
                }
                i += 1;
            }
            State::BlockComment => {
                if c == '*' && nxt == '/' {
                    state = State::Code;
                    out.push_str("  ");
                    i += 2;
                } else {
                    out.push(if c == '\n' { '\n' } else { ' ' });
                    i += 1;
                }
            }
            State::StringLit => {
                if c == '\\' && nxt != '\0' {
                    out.push_str("  ");
                    i += 2;
                } else if c == quote {
                    state = State::Code;
                    out.push(' ');
                    i += 1;
                } else {
                    out.push(if c == '\n' { '\n' } else { ' ' });
                    i += 1;
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_line_count() {
        let src = "a // c\n\"str\"\n/* x\ny */ b";
        let out = strip_comments_and_strings(src);
        assert_eq!(out.matches('\n').count(), src.matches('\n').count());
        assert!(!out.contains("str"));
    }

    #[test]
    fn slash_in_string_not_a_comment() {
        let out = strip_comments_and_strings("x = \"a // b\"; y = 1;");
        assert!(out.contains("y = 1"));
        assert!(!out.contains("a // b"));
    }
}
