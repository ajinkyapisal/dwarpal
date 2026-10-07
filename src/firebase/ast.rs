//! Syntax tree for Firebase Security Rules (Firestore and Cloud Storage).

#[derive(Debug, Clone)]
pub struct Ruleset {
    pub services: Vec<Service>,
}

#[derive(Debug, Clone)]
pub struct Service {
    /// `cloud.firestore` or `firebase.storage`.
    pub name: String,
    pub items: Vec<Item>,
}

#[derive(Debug, Clone)]
pub enum Item {
    Match(Match),
    Allow(Allow),
    Function(Function),
}

#[derive(Debug, Clone)]
pub struct Match {
    pub path: Vec<Segment>,
    pub items: Vec<Item>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Segment {
    Literal(String),
    /// `{name}` matches one segment; `{name=**}` matches any number.
    Wildcard {
        name: String,
        recursive: bool,
    },
}

#[derive(Debug, Clone)]
pub struct Allow {
    /// read, write, get, list, create, update, delete.
    pub methods: Vec<String>,
    /// None means `allow read;` with no condition: always allowed.
    pub condition: Option<Expr>,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub params: Vec<String>,
    pub lets: Vec<(String, Expr)>,
    pub body: Expr,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Bool(bool),
    Null,
    Int(i64),
    Float(f64),
    Str(String),
    Ident(String),
    /// `/databases/$(database)/documents/users/$(request.auth.uid)`
    Path(Vec<PathPart>),
    Member(Box<Expr>, String),
    Index(Box<Expr>, Box<Expr>),
    Call(Box<Expr>, Vec<Expr>),
    Unary(&'static str, Box<Expr>),
    Binary(&'static str, Box<Expr>, Box<Expr>),
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
    List(Vec<Expr>),
    Map(Vec<(Expr, Expr)>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum PathPart {
    Literal(String),
    Expr(Expr),
}

impl Expr {
    /// Dotted name of a member chain, such as "request.auth.uid".
    pub fn dotted(&self) -> Option<String> {
        match self {
            Expr::Ident(name) => Some(name.clone()),
            Expr::Member(base, field) => base.dotted().map(|b| format!("{b}.{field}")),
            _ => None,
        }
    }

    /// Visit this expression and every sub-expression.
    pub fn walk<'a>(&'a self, visit: &mut dyn FnMut(&'a Expr)) {
        visit(self);
        match self {
            Expr::Member(base, _) => base.walk(visit),
            Expr::Index(base, index) => {
                base.walk(visit);
                index.walk(visit);
            }
            Expr::Call(callee, args) => {
                callee.walk(visit);
                args.iter().for_each(|a| a.walk(visit));
            }
            Expr::Unary(_, e) => e.walk(visit),
            Expr::Binary(_, l, r) => {
                l.walk(visit);
                r.walk(visit);
            }
            Expr::Ternary(c, a, b) => {
                c.walk(visit);
                a.walk(visit);
                b.walk(visit);
            }
            Expr::List(items) => items.iter().for_each(|e| e.walk(visit)),
            Expr::Map(entries) => entries.iter().for_each(|(k, v)| {
                k.walk(visit);
                v.walk(visit);
            }),
            Expr::Path(parts) => parts.iter().for_each(|p| {
                if let PathPart::Expr(e) = p {
                    e.walk(visit)
                }
            }),
            _ => {}
        }
    }

    pub fn any(&self, pred: &dyn Fn(&Expr) -> bool) -> bool {
        let mut found = false;
        self.walk(&mut |e| found |= pred(e));
        found
    }
}
