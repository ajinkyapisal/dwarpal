//! Recursive-descent parser for Firebase Security Rules.

use super::ast::*;
use super::lexer::{Tok, Token, lex};

#[derive(Debug)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

pub fn parse(src: &str) -> std::result::Result<Ruleset, ParseError> {
    let tokens = lex(src).map_err(|e| ParseError {
        line: e.line,
        message: e.message,
    })?;
    Parser { tokens, pos: 0 }.ruleset()
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

type Result<T> = std::result::Result<T, ParseError>;

impl Parser {
    fn peek(&self) -> &Tok {
        &self.tokens[self.pos].tok
    }

    fn line(&self) -> usize {
        self.tokens[self.pos].line
    }

    fn next(&mut self) -> Tok {
        let tok = self.tokens[self.pos].tok.clone();
        if self.pos < self.tokens.len() - 1 {
            self.pos += 1;
        }
        tok
    }

    fn error<T>(&self, message: impl Into<String>) -> Result<T> {
        Err(ParseError {
            line: self.line(),
            message: message.into(),
        })
    }

    fn is_punct(&self, p: &str) -> bool {
        matches!(self.peek(), Tok::Punct(q) if *q == p)
    }

    fn is_word(&self, w: &str) -> bool {
        matches!(self.peek(), Tok::Ident(x) if x == w)
    }

    fn eat_punct(&mut self, p: &str) -> bool {
        if self.is_punct(p) {
            self.next();
            true
        } else {
            false
        }
    }

    fn expect_punct(&mut self, p: &str) -> Result<()> {
        if self.eat_punct(p) {
            Ok(())
        } else {
            self.error(format!("expected '{p}', found {}", describe(self.peek())))
        }
    }

    fn ident(&mut self) -> Result<String> {
        match self.next() {
            Tok::Ident(name) => Ok(name),
            other => self.error(format!("expected a name, found {}", describe(&other))),
        }
    }

    fn ruleset(&mut self) -> Result<Ruleset> {
        let mut services = Vec::new();
        loop {
            match self.peek().clone() {
                Tok::Eof => break,
                Tok::Ident(w) if w == "rules_version" => {
                    self.next();
                    self.expect_punct("=")?;
                    match self.next() {
                        Tok::Str(_) => {}
                        other => {
                            return self.error(format!(
                                "expected a version string, found {}",
                                describe(&other)
                            ));
                        }
                    }
                    self.eat_punct(";");
                }
                Tok::Ident(w) if w == "service" => services.push(self.service()?),
                other => {
                    return self.error(format!("expected 'service', found {}", describe(&other)));
                }
            }
        }
        Ok(Ruleset { services })
    }

    fn service(&mut self) -> Result<Service> {
        self.next(); // service
        let mut name = self.ident()?;
        while self.eat_punct(".") {
            name.push('.');
            name.push_str(&self.ident()?);
        }
        let items = self.block()?;
        Ok(Service { name, items })
    }

    fn block(&mut self) -> Result<Vec<Item>> {
        self.expect_punct("{")?;
        let mut items = Vec::new();
        while !self.eat_punct("}") {
            if matches!(self.peek(), Tok::Eof) {
                return self.error("unexpected end of file; missing '}'");
            }
            if self.eat_punct(";") {
                continue;
            }
            items.push(self.item()?);
        }
        Ok(items)
    }

    fn item(&mut self) -> Result<Item> {
        let line = self.line();
        if self.is_word("match") {
            self.next();
            let path = match self.next() {
                Tok::Path(p) => parse_match_path(&p),
                other => {
                    return self.error(format!(
                        "expected a path after 'match', found {}",
                        describe(&other)
                    ));
                }
            };
            let items = self.block()?;
            return Ok(Item::Match(Match { path, items }));
        }
        if self.is_word("allow") {
            self.next();
            let mut methods = vec![self.ident()?];
            while self.eat_punct(",") {
                methods.push(self.ident()?);
            }
            let condition = if self.eat_punct(":") {
                if !self.is_word("if") {
                    return self.error("expected 'if' after ':'");
                }
                self.next();
                Some(self.expr()?)
            } else {
                None
            };
            self.eat_punct(";");
            return Ok(Item::Allow(Allow {
                methods,
                condition,
                line,
            }));
        }
        if self.is_word("function") {
            self.next();
            let name = self.ident()?;
            self.expect_punct("(")?;
            let mut params = Vec::new();
            while !self.eat_punct(")") {
                params.push(self.ident()?);
                self.eat_punct(",");
            }
            self.expect_punct("{")?;
            let mut lets = Vec::new();
            while self.is_word("let") {
                self.next();
                let var = self.ident()?;
                self.expect_punct("=")?;
                lets.push((var, self.expr()?));
                self.eat_punct(";");
            }
            if !self.is_word("return") {
                return self.error("expected 'return' in function body");
            }
            self.next();
            let body = self.expr()?;
            self.eat_punct(";");
            self.expect_punct("}")?;
            return Ok(Item::Function(Function {
                name,
                params,
                lets,
                body,
            }));
        }
        self.error(format!(
            "expected 'match', 'allow' or 'function', found {}",
            describe(self.peek())
        ))
    }

    // Expressions, lowest precedence first.

    fn expr(&mut self) -> Result<Expr> {
        let cond = self.or()?;
        if self.eat_punct("?") {
            let a = self.expr()?;
            self.expect_punct(":")?;
            let b = self.expr()?;
            return Ok(Expr::Ternary(Box::new(cond), Box::new(a), Box::new(b)));
        }
        Ok(cond)
    }

    fn or(&mut self) -> Result<Expr> {
        let mut left = self.and()?;
        while self.eat_punct("||") {
            left = Expr::Binary("||", Box::new(left), Box::new(self.and()?));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr> {
        let mut left = self.relation()?;
        while self.eat_punct("&&") {
            left = Expr::Binary("&&", Box::new(left), Box::new(self.relation()?));
        }
        Ok(left)
    }

    fn relation(&mut self) -> Result<Expr> {
        let mut left = self.additive()?;
        loop {
            let op = match self.peek() {
                Tok::Punct(p) if matches!(*p, "==" | "!=" | "<" | "<=" | ">" | ">=") => *p,
                Tok::Ident(w) if w == "in" => "in",
                Tok::Ident(w) if w == "is" => "is",
                _ => break,
            };
            self.next();
            left = Expr::Binary(op, Box::new(left), Box::new(self.additive()?));
        }
        Ok(left)
    }

    fn additive(&mut self) -> Result<Expr> {
        let mut left = self.multiplicative()?;
        loop {
            let op = match self.peek() {
                Tok::Punct(p) if matches!(*p, "+" | "-") => *p,
                _ => break,
            };
            self.next();
            left = Expr::Binary(op, Box::new(left), Box::new(self.multiplicative()?));
        }
        Ok(left)
    }

    fn multiplicative(&mut self) -> Result<Expr> {
        let mut left = self.unary()?;
        loop {
            let op = match self.peek() {
                Tok::Punct(p) if matches!(*p, "*" | "/" | "%") => *p,
                _ => break,
            };
            self.next();
            left = Expr::Binary(op, Box::new(left), Box::new(self.unary()?));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr> {
        if self.eat_punct("!") {
            return Ok(Expr::Unary("!", Box::new(self.unary()?)));
        }
        if self.eat_punct("-") {
            return Ok(Expr::Unary("-", Box::new(self.unary()?)));
        }
        self.postfix()
    }

    fn postfix(&mut self) -> Result<Expr> {
        let mut e = self.primary()?;
        loop {
            if self.eat_punct(".") {
                e = Expr::Member(Box::new(e), self.ident()?);
            } else if self.eat_punct("[") {
                let index = self.expr()?;
                self.expect_punct("]")?;
                e = Expr::Index(Box::new(e), Box::new(index));
            } else if self.eat_punct("(") {
                let mut args = Vec::new();
                while !self.eat_punct(")") {
                    args.push(self.expr()?);
                    if !self.is_punct(")") {
                        self.expect_punct(",")?;
                    }
                }
                e = Expr::Call(Box::new(e), args);
            } else {
                return Ok(e);
            }
        }
    }

    fn primary(&mut self) -> Result<Expr> {
        let line = self.line();
        match self.next() {
            Tok::Ident(w) => Ok(match w.as_str() {
                "true" => Expr::Bool(true),
                "false" => Expr::Bool(false),
                "null" => Expr::Null,
                _ => Expr::Ident(w),
            }),
            Tok::Int(n) => Ok(Expr::Int(n)),
            Tok::Float(n) => Ok(Expr::Float(n)),
            Tok::Str(s) => Ok(Expr::Str(s)),
            Tok::Path(p) => parse_expr_path(&p).map_err(|message| ParseError { line, message }),
            Tok::Punct("(") => {
                let e = self.expr()?;
                self.expect_punct(")")?;
                Ok(e)
            }
            Tok::Punct("[") => {
                let mut items = Vec::new();
                while !self.eat_punct("]") {
                    items.push(self.expr()?);
                    if !self.is_punct("]") {
                        self.expect_punct(",")?;
                    }
                }
                Ok(Expr::List(items))
            }
            Tok::Punct("{") => {
                let mut entries = Vec::new();
                while !self.eat_punct("}") {
                    let key = self.expr()?;
                    self.expect_punct(":")?;
                    entries.push((key, self.expr()?));
                    if !self.is_punct("}") {
                        self.expect_punct(",")?;
                    }
                }
                Ok(Expr::Map(entries))
            }
            other => Err(ParseError {
                line,
                message: format!("expected an expression, found {}", describe(&other)),
            }),
        }
    }
}

fn describe(tok: &Tok) -> String {
    match tok {
        Tok::Ident(w) => format!("'{w}'"),
        Tok::Int(n) => n.to_string(),
        Tok::Float(n) => n.to_string(),
        Tok::Str(s) => format!("string {s:?}"),
        Tok::Path(p) => format!("path {p}"),
        Tok::Punct(p) => format!("'{p}'"),
        Tok::Eof => "end of file".into(),
    }
}

fn split_path(path: &str) -> Vec<String> {
    // Split on '/' outside $( ... ) and { ... }.
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0;
    for ch in path.chars() {
        match ch {
            '(' | '{' => depth += 1,
            ')' | '}' => depth -= 1,
            '/' if depth == 0 => {
                if !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

fn parse_match_path(path: &str) -> Vec<Segment> {
    split_path(path)
        .into_iter()
        .map(
            |part| match part.strip_prefix('{').and_then(|p| p.strip_suffix('}')) {
                Some(inner) => match inner.strip_suffix("=**") {
                    Some(name) => Segment::Wildcard {
                        name: name.trim().into(),
                        recursive: true,
                    },
                    None => Segment::Wildcard {
                        name: inner.trim().into(),
                        recursive: false,
                    },
                },
                None => Segment::Literal(part),
            },
        )
        .collect()
}

fn parse_expr_path(path: &str) -> std::result::Result<Expr, String> {
    let mut parts = Vec::new();
    for part in split_path(path) {
        match part.strip_prefix("$(").and_then(|p| p.strip_suffix(')')) {
            Some(inner) => {
                let tokens = lex(inner).map_err(|e| e.message)?;
                let mut parser = Parser { tokens, pos: 0 };
                let e = parser.expr().map_err(|e| e.message)?;
                parts.push(PathPart::Expr(e));
            }
            None => parts.push(PathPart::Literal(part)),
        }
    }
    Ok(Expr::Path(parts))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
        rules_version = '2';
        service cloud.firestore {
          match /databases/{database}/documents {
            function isOwner(uid) {
              let me = request.auth.uid;
              return me != null && me == uid;
            }
            match /users/{userId} {
              allow read;
              allow update, delete: if isOwner(userId) && request.resource.data.keys().hasOnly(['name']);
            }
            match /{document=**} {
              allow read: if get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin';
            }
          }
        }
    "#;

    #[test]
    fn parses_a_full_ruleset() {
        let rs = parse(RULES).unwrap();
        assert_eq!(rs.services[0].name, "cloud.firestore");
        let Item::Match(db) = &rs.services[0].items[0] else {
            panic!()
        };
        assert_eq!(db.path[2], Segment::Literal("documents".into()));
        assert!(
            matches!(&db.items[0], Item::Function(f) if f.name == "isOwner" && f.lets.len() == 1)
        );
        let Item::Match(users) = &db.items[1] else {
            panic!()
        };
        let Item::Allow(read) = &users.items[0] else {
            panic!()
        };
        assert!(read.condition.is_none());
        let Item::Match(all) = &db.items[2] else {
            panic!()
        };
        assert_eq!(
            all.path,
            vec![Segment::Wildcard {
                name: "document".into(),
                recursive: true
            }]
        );
    }

    #[test]
    fn reports_errors_with_lines() {
        let err =
            parse("service cloud.firestore {\n match /a {\n allow read: if ;\n }\n}").unwrap_err();
        assert_eq!(err.line, 3);
    }

    #[test]
    fn precedence() {
        let rs = parse("service s { match /a { allow read: if a || b && c == d; } }").unwrap();
        let Item::Match(m) = &rs.services[0].items[0] else {
            panic!()
        };
        let Item::Allow(a) = &m.items[0] else {
            panic!()
        };
        let Some(Expr::Binary("||", _, right)) = &a.condition else {
            panic!("{:?}", a.condition)
        };
        assert!(matches!(**right, Expr::Binary("&&", _, _)));
    }
}
