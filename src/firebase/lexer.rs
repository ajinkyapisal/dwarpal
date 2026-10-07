//! Tokenizer for the Firebase Security Rules language.

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    Ident(String),
    Int(i64),
    Float(f64),
    Str(String),
    /// A path such as `/users/{userId}` or `/databases/$(database)/documents`.
    Path(String),
    Punct(&'static str),
    Eof,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub tok: Tok,
    pub line: usize,
}

#[derive(Debug)]
pub struct LexError {
    pub line: usize,
    pub message: String,
}

const PUNCTS: [&str; 26] = [
    "&&", "||", "==", "!=", "<=", ">=", "{", "}", "(", ")", "[", "]", ";", ",", ".", ":", "?", "!",
    "<", ">", "=", "+", "-", "*", "/", "%",
];

/// A `/` starts a path, not a division, when it comes where an operand is
/// expected and is directly followed by a path segment.
fn path_can_start(prev: Option<&Tok>) -> bool {
    match prev {
        None => true,
        Some(Tok::Ident(word)) => matches!(word.as_str(), "match" | "return" | "in" | "is" | "if"),
        Some(Tok::Punct(p)) => !matches!(*p, ")" | "]" | "}"),
        Some(_) => false,
    }
}

pub fn lex(src: &str) -> Result<Vec<Token>, LexError> {
    let chars: Vec<char> = src.chars().collect();
    let mut tokens: Vec<Token> = Vec::new();
    let mut i = 0;
    let mut line = 1;

    while i < chars.len() {
        let c = chars[i];
        if c == '\n' {
            line += 1;
            i += 1;
            continue;
        }
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        // Comments.
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                if chars[i] == '\n' {
                    line += 1;
                }
                i += 1;
            }
            i += 2;
            continue;
        }
        // Paths.
        if c == '/'
            && path_can_start(tokens.last().map(|t| &t.tok))
            && matches!(chars.get(i + 1), Some(n) if n.is_alphanumeric() || matches!(n, '$' | '{' | '_' | '('))
        {
            let start_line = line;
            let mut path = String::new();
            while i < chars.len() && chars[i] == '/' {
                path.push('/');
                i += 1;
                match chars.get(i) {
                    Some('$') if chars.get(i + 1) == Some(&'(') => {
                        let mut depth = 0;
                        while i < chars.len() {
                            let ch = chars[i];
                            path.push(ch);
                            i += 1;
                            if ch == '(' {
                                depth += 1;
                            } else if ch == ')' {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                        }
                    }
                    Some('{') => {
                        while i < chars.len() && chars[i] != '}' {
                            path.push(chars[i]);
                            i += 1;
                        }
                        if i < chars.len() {
                            path.push('}');
                            i += 1;
                        }
                    }
                    Some('(') => {
                        // A literal such as (default).
                        while i < chars.len() && chars[i] != ')' {
                            path.push(chars[i]);
                            i += 1;
                        }
                        if i < chars.len() {
                            path.push(')');
                            i += 1;
                        }
                    }
                    _ => {
                        while i < chars.len()
                            && (chars[i].is_alphanumeric()
                                || matches!(chars[i], '_' | '-' | '.' | '~' | '@' | '*'))
                        {
                            path.push(chars[i]);
                            i += 1;
                        }
                    }
                }
            }
            tokens.push(Token {
                tok: Tok::Path(path),
                line: start_line,
            });
            continue;
        }
        // Strings.
        if c == '\'' || c == '"' {
            let quote = c;
            let mut s = String::new();
            i += 1;
            while i < chars.len() && chars[i] != quote {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                    s.push(match chars[i] {
                        'n' => '\n',
                        't' => '\t',
                        other => other,
                    });
                } else {
                    if chars[i] == '\n' {
                        line += 1;
                    }
                    s.push(chars[i]);
                }
                i += 1;
            }
            if i >= chars.len() {
                return Err(LexError {
                    line,
                    message: "unterminated string".into(),
                });
            }
            i += 1;
            tokens.push(Token {
                tok: Tok::Str(s),
                line,
            });
            continue;
        }
        // Numbers.
        if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let is_float = chars.get(i) == Some(&'.')
                && matches!(chars.get(i + 1), Some(d) if d.is_ascii_digit());
            if is_float {
                i += 1;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
            }
            let text: String = chars[start..i].iter().collect();
            let tok = if is_float {
                Tok::Float(text.parse().unwrap_or(0.0))
            } else {
                Tok::Int(text.parse().unwrap_or(i64::MAX))
            };
            tokens.push(Token { tok, line });
            continue;
        }
        // Identifiers.
        if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            tokens.push(Token {
                tok: Tok::Ident(chars[start..i].iter().collect()),
                line,
            });
            continue;
        }
        // Punctuation, longest first.
        let rest: String = chars[i..chars.len().min(i + 2)].iter().collect();
        match PUNCTS.iter().find(|p| rest.starts_with(**p)) {
            Some(p) => {
                tokens.push(Token {
                    tok: Tok::Punct(p),
                    line,
                });
                i += p.len();
            }
            None => {
                return Err(LexError {
                    line,
                    message: format!("unexpected character {c:?}"),
                });
            }
        }
    }
    tokens.push(Token {
        tok: Tok::Eof,
        line,
    });
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(src: &str) -> Vec<Tok> {
        lex(src).unwrap().into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn match_paths_and_division() {
        assert_eq!(
            toks("match /users/{userId} { allow read: if a / 2 > 1; }")[..2],
            [
                Tok::Ident("match".into()),
                Tok::Path("/users/{userId}".into())
            ]
        );
        assert!(toks("a / 2").contains(&Tok::Punct("/")));
    }

    #[test]
    fn expression_paths_with_interpolation() {
        let t = toks("get(/databases/$(database)/documents/users/$(request.auth.uid)).data");
        assert_eq!(
            t[2],
            Tok::Path("/databases/$(database)/documents/users/$(request.auth.uid)".into())
        );
        assert_eq!(t[3], Tok::Punct(")"));
    }

    #[test]
    fn comments_and_lines() {
        let tokens = lex("// one\n/* two\nthree */ allow").unwrap();
        assert_eq!(tokens[0].tok, Tok::Ident("allow".into()));
        assert_eq!(tokens[0].line, 3);
    }
}
