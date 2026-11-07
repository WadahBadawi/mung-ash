use mash_core::{DissectedPacket, FieldValue};
use mash_dissect::Registry;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

/// Structured diagnostic when a display filter fails to parse or validate (`FLT-07`).
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub struct FilterDiagnostic {
    pub span: (usize, usize),
    pub message: String,
    pub suggestions: Vec<String>,
}

impl fmt::Display for FilterDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Filter error at {}..{}: {}",
            self.span.0, self.span.1, self.message
        )?;
        if !self.suggestions.is_empty() {
            write!(f, " (did you mean: {}?)", self.suggestions.join(", "))?;
        }
        Ok(())
    }
}

/// Slice specification on a field (`field[start:len]` or `field[start..end]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceSpec {
    Index(usize),
    OffsetLen { offset: usize, len: usize },
    Range { start: usize, end_inclusive: usize },
}

/// A field reference in a display filter expression (`FLT-01`, `FLT-05`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRef {
    pub abbrev: String,
    /// Optional 1-based layer selector (e.g., `ip.src#2`).
    pub layer: Option<usize>,
    /// Optional byte/character slice (`eth.src[0:3]`).
    pub slice: Option<SliceSpec>,
}

/// Built-in display filter functions (`FLT-06`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterFunc {
    Len,
    Count,
    Upper,
    Lower,
    String,
}

/// Value operand in a filter comparison.
#[derive(Debug, Clone)]
pub enum Operand {
    Field(FieldRef),
    FuncCall(FilterFunc, FieldRef),
    BitwiseAnd(Box<Operand>, u64),
    Literal(LiteralVal),
}

/// Typed literal in a display filter expression.
#[derive(Debug, Clone, PartialEq)]
pub enum LiteralVal {
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    Str(String),
    Ipv4([u8; 4]),
    Ipv4Cidr { net: u32, mask: u32 },
    Ipv6([u8; 16]),
    Bytes(Vec<u8>),
}

/// Comparison operators (`FLT-02`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    Contains,
    BitwiseAndNonZero,
}

/// Element inside an `in { ... }` set (`FLT-04`).
#[derive(Debug, Clone)]
pub enum SetItem {
    Single(LiteralVal),
    Range(LiteralVal, LiteralVal),
}

/// Compiled Display Filter AST (`FLT-01`..`FLT-08`).
#[derive(Debug, Clone)]
pub enum FilterExpr {
    MatchAll,
    Exists(FieldRef),
    Not(Box<FilterExpr>),
    And(Box<FilterExpr>, Box<FilterExpr>),
    Or(Box<FilterExpr>, Box<FilterExpr>),
    Xor(Box<FilterExpr>, Box<FilterExpr>),
    Compare {
        lhs: Operand,
        op: CmpOp,
        rhs: Operand,
    },
    Matches {
        lhs: Operand,
        pattern: String,
        regex: Regex,
    },
    InSet {
        lhs: Operand,
        items: Vec<SetItem>,
    },
}

/// Compiled display filter ready for fast per-packet evaluation.
#[derive(Debug, Clone)]
pub struct CompiledFilter {
    pub source: String,
    pub expr: FilterExpr,
}

impl CompiledFilter {
    /// Compile and validate a display filter string against `registry` (`FLT-07`).
    pub fn compile(source: &str, registry: Option<&Registry>) -> Result<Self, FilterDiagnostic> {
        let trimmed = source.trim();
        if trimmed.is_empty() {
            return Ok(Self {
                source: String::new(),
                expr: FilterExpr::MatchAll,
            });
        }
        let tokens = tokenize(source)?;
        let mut parser = Parser {
            source,
            tokens: &tokens,
            pos: 0,
            registry,
        };
        let expr = parser.parse_or()?;
        if parser.pos < parser.tokens.len() {
            let tok = &parser.tokens[parser.pos];
            return Err(FilterDiagnostic {
                span: tok.span,
                message: format!("Unexpected token '{}'", tok.raw),
                suggestions: Vec::new(),
            });
        }
        Ok(Self {
            source: trimmed.to_string(),
            expr,
        })
    }

    /// Evaluate the compiled display filter against a `DissectedPacket`.
    pub fn matches(&self, pkt: &DissectedPacket) -> bool {
        eval_expr(&self.expr, pkt)
    }
}

/// Return autocomplete candidates for the current token prefix (`FLT-07`).
pub fn autocomplete_filter(input: &str, registry: &Registry, max_items: usize) -> Vec<String> {
    let last_token = input
        .rsplit(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | '!' | '=' | '<' | '>' | ','))
        .next()
        .unwrap_or("")
        .trim();

    let mut out = Vec::new();
    // Multi-field aliases first
    const ALIASES: &[&str] = &["ip.addr", "ipv6.addr", "tcp.port", "udp.port", "eth.addr"];
    for &alias in ALIASES {
        if alias.starts_with(last_token) {
            out.push(alias.to_string());
        }
    }
    for f in registry.fields() {
        if f.abbrev.starts_with(last_token) && !out.contains(&f.abbrev) {
            out.push(f.abbrev.clone());
            if out.len() >= max_items {
                break;
            }
        }
    }
    out.sort();
    out.truncate(max_items);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokKind {
    Ident,
    StringLit,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Colon,
    DotDot,
    Hash,
    Not,
    And,
    Or,
    Xor,
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    Contains,
    Matches,
    In,
    Amp,
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokKind,
    raw: String,
    span: (usize, usize),
}

fn tokenize(input: &str) -> Result<Vec<Token>, FilterDiagnostic> {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut tokens = Vec::new();

    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        match b {
            b'(' => {
                i += 1;
                tokens.push(Token {
                    kind: TokKind::LParen,
                    raw: "(".to_string(),
                    span: (start, i),
                });
            }
            b')' => {
                i += 1;
                tokens.push(Token {
                    kind: TokKind::RParen,
                    raw: ")".to_string(),
                    span: (start, i),
                });
            }
            b'{' => {
                i += 1;
                tokens.push(Token {
                    kind: TokKind::LBrace,
                    raw: "{".to_string(),
                    span: (start, i),
                });
            }
            b'}' => {
                i += 1;
                tokens.push(Token {
                    kind: TokKind::RBrace,
                    raw: "}".to_string(),
                    span: (start, i),
                });
            }
            b'[' => {
                i += 1;
                tokens.push(Token {
                    kind: TokKind::LBracket,
                    raw: "[".to_string(),
                    span: (start, i),
                });
            }
            b']' => {
                i += 1;
                tokens.push(Token {
                    kind: TokKind::RBracket,
                    raw: "]".to_string(),
                    span: (start, i),
                });
            }
            b',' => {
                i += 1;
                tokens.push(Token {
                    kind: TokKind::Comma,
                    raw: ",".to_string(),
                    span: (start, i),
                });
            }
            b'#' => {
                i += 1;
                tokens.push(Token {
                    kind: TokKind::Hash,
                    raw: "#".to_string(),
                    span: (start, i),
                });
            }
            b'~' => {
                i += 1;
                tokens.push(Token {
                    kind: TokKind::Matches,
                    raw: "~".to_string(),
                    span: (start, i),
                });
            }
            b'"' | b'\'' => {
                let quote = b;
                i += 1;
                let mut s = String::new();
                let mut closed = false;
                while i < bytes.len() {
                    let ch = input[i..].chars().next().unwrap_or('\0');
                    i += ch.len_utf8();
                    if ch as u8 == quote {
                        closed = true;
                        break;
                    }
                    if ch == '\\' && i < bytes.len() {
                        let esc = input[i..].chars().next().unwrap_or('\0');
                        i += esc.len_utf8();
                        match esc {
                            'n' => s.push('\n'),
                            'r' => s.push('\r'),
                            't' => s.push('\t'),
                            other => s.push(other),
                        }
                    } else {
                        s.push(ch);
                    }
                }
                if !closed {
                    return Err(FilterDiagnostic {
                        span: (start, i),
                        message: "Unterminated string literal".to_string(),
                        suggestions: Vec::new(),
                    });
                }
                tokens.push(Token {
                    kind: TokKind::StringLit,
                    raw: s,
                    span: (start, i),
                });
            }
            b'!' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    i += 2;
                    tokens.push(Token {
                        kind: TokKind::Ne,
                        raw: "!=".to_string(),
                        span: (start, i),
                    });
                } else {
                    i += 1;
                    tokens.push(Token {
                        kind: TokKind::Not,
                        raw: "!".to_string(),
                        span: (start, i),
                    });
                }
            }
            b'=' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    i += 2;
                } else {
                    i += 1;
                }
                tokens.push(Token {
                    kind: TokKind::Eq,
                    raw: "==".to_string(),
                    span: (start, i),
                });
            }
            b'>' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    i += 2;
                    tokens.push(Token {
                        kind: TokKind::Ge,
                        raw: ">=".to_string(),
                        span: (start, i),
                    });
                } else {
                    i += 1;
                    tokens.push(Token {
                        kind: TokKind::Gt,
                        raw: ">".to_string(),
                        span: (start, i),
                    });
                }
            }
            b'<' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    i += 2;
                    tokens.push(Token {
                        kind: TokKind::Le,
                        raw: "<=".to_string(),
                        span: (start, i),
                    });
                } else {
                    i += 1;
                    tokens.push(Token {
                        kind: TokKind::Lt,
                        raw: "<".to_string(),
                        span: (start, i),
                    });
                }
            }
            b'&' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'&' {
                    i += 2;
                    tokens.push(Token {
                        kind: TokKind::And,
                        raw: "&&".to_string(),
                        span: (start, i),
                    });
                } else {
                    i += 1;
                    tokens.push(Token {
                        kind: TokKind::Amp,
                        raw: "&".to_string(),
                        span: (start, i),
                    });
                }
            }
            b'|' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'|' {
                    i += 2;
                    tokens.push(Token {
                        kind: TokKind::Or,
                        raw: "||".to_string(),
                        span: (start, i),
                    });
                } else {
                    return Err(FilterDiagnostic {
                        span: (start, start + 1),
                        message: "Unexpected '|', use '||' for logical OR".to_string(),
                        suggestions: Vec::new(),
                    });
                }
            }
            b'^' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'^' {
                    i += 2;
                } else {
                    i += 1;
                }
                tokens.push(Token {
                    kind: TokKind::Xor,
                    raw: "^^".to_string(),
                    span: (start, i),
                });
            }
            b'.' if i + 1 < bytes.len() && bytes[i + 1] == b'.' => {
                i += 2;
                tokens.push(Token {
                    kind: TokKind::DotDot,
                    raw: "..".to_string(),
                    span: (start, i),
                });
            }
            _ => {
                // Read identifier, number, IPv4/CIDR, IPv6, or MAC literal
                while i < bytes.len() {
                    let c = bytes[i];
                    if c.is_ascii_whitespace()
                        || matches!(
                            c,
                            b'(' | b')'
                                | b'{'
                                | b'}'
                                | b'['
                                | b']'
                                | b','
                                | b'#'
                                | b'!'
                                | b'='
                                | b'>'
                                | b'<'
                                | b'&'
                                | b'|'
                                | b'^'
                                | b'~'
                                | b'"'
                                | b'\''
                        )
                    {
                        break;
                    }
                    if c == b'.' && i + 1 < bytes.len() && bytes[i + 1] == b'.' {
                        break;
                    }
                    i += 1;
                }
                let word = &input[start..i];
                if word == ":" {
                    tokens.push(Token {
                        kind: TokKind::Colon,
                        raw: ":".to_string(),
                        span: (start, i),
                    });
                    continue;
                }
                let kind = match word.to_ascii_lowercase().as_str() {
                    "and" => TokKind::And,
                    "or" => TokKind::Or,
                    "xor" => TokKind::Xor,
                    "not" => TokKind::Not,
                    "eq" => TokKind::Eq,
                    "ne" => TokKind::Ne,
                    "gt" => TokKind::Gt,
                    "lt" => TokKind::Lt,
                    "ge" => TokKind::Ge,
                    "le" => TokKind::Le,
                    "contains" => TokKind::Contains,
                    "matches" => TokKind::Matches,
                    "in" => TokKind::In,
                    _ => TokKind::Ident,
                };
                tokens.push(Token {
                    kind,
                    raw: word.to_string(),
                    span: (start, i),
                });
            }
        }
    }

    Ok(tokens)
}

struct Parser<'a> {
    source: &'a str,
    tokens: &'a [Token],
    pos: usize,
    registry: Option<&'a Registry>,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<&'a Token> {
        let t = self.tokens.get(self.pos)?;
        self.pos += 1;
        Some(t)
    }

    fn parse_or(&mut self) -> Result<FilterExpr, FilterDiagnostic> {
        let mut left = self.parse_xor()?;
        while let Some(tok) = self.peek() {
            if tok.kind == TokKind::Or {
                self.next();
                let right = self.parse_xor()?;
                left = FilterExpr::Or(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_xor(&mut self) -> Result<FilterExpr, FilterDiagnostic> {
        let mut left = self.parse_and()?;
        while let Some(tok) = self.peek() {
            if tok.kind == TokKind::Xor {
                self.next();
                let right = self.parse_and()?;
                left = FilterExpr::Xor(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<FilterExpr, FilterDiagnostic> {
        let mut left = self.parse_unary()?;
        while let Some(tok) = self.peek() {
            if tok.kind == TokKind::And {
                self.next();
                let right = self.parse_unary()?;
                left = FilterExpr::And(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<FilterExpr, FilterDiagnostic> {
        if let Some(tok) = self.peek() {
            if tok.kind == TokKind::Not {
                self.next();
                let inner = self.parse_unary()?;
                return Ok(FilterExpr::Not(Box::new(inner)));
            }
            if tok.kind == TokKind::LParen {
                self.next();
                let inner = self.parse_or()?;
                match self.next() {
                    Some(close) if close.kind == TokKind::RParen => return Ok(inner),
                    other => {
                        let span = other
                            .map(|t| t.span)
                            .unwrap_or((self.source.len(), self.source.len()));
                        return Err(FilterDiagnostic {
                            span,
                            message: "Expected closing ')'".to_string(),
                            suggestions: Vec::new(),
                        });
                    }
                }
            }
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<FilterExpr, FilterDiagnostic> {
        let lhs = self.parse_operand(true)?;

        // Check for comparison, `in { ... }`, or `matches`
        if let Some(tok) = self.peek() {
            match tok.kind {
                TokKind::Eq
                | TokKind::Ne
                | TokKind::Gt
                | TokKind::Lt
                | TokKind::Ge
                | TokKind::Le
                | TokKind::Contains => {
                    let op = match self.next().map(|t| &t.kind) {
                        Some(TokKind::Eq) => CmpOp::Eq,
                        Some(TokKind::Ne) => CmpOp::Ne,
                        Some(TokKind::Gt) => CmpOp::Gt,
                        Some(TokKind::Lt) => CmpOp::Lt,
                        Some(TokKind::Ge) => CmpOp::Ge,
                        Some(TokKind::Le) => CmpOp::Le,
                        _ => CmpOp::Contains,
                    };
                    let rhs = self.parse_operand(false)?;
                    return Ok(FilterExpr::Compare { lhs, op, rhs });
                }
                TokKind::Matches => {
                    let op_tok = self.next().unwrap();
                    let pat_tok = self.next().ok_or_else(|| FilterDiagnostic {
                        span: op_tok.span,
                        message: "Expected regex pattern after 'matches'".to_string(),
                        suggestions: Vec::new(),
                    })?;
                    let regex = Regex::new(&pat_tok.raw).map_err(|e| FilterDiagnostic {
                        span: pat_tok.span,
                        message: format!("Invalid regular expression: {e}"),
                        suggestions: Vec::new(),
                    })?;
                    return Ok(FilterExpr::Matches {
                        lhs,
                        pattern: pat_tok.raw.clone(),
                        regex,
                    });
                }
                TokKind::In => {
                    let in_tok = self.next().unwrap();
                    match self.next() {
                        Some(b) if b.kind == TokKind::LBrace => {}
                        _ => {
                            return Err(FilterDiagnostic {
                                span: in_tok.span,
                                message: "Expected '{' after 'in'".to_string(),
                                suggestions: Vec::new(),
                            });
                        }
                    }
                    let mut items = Vec::new();
                    while let Some(t) = self.peek() {
                        if t.kind == TokKind::RBrace {
                            self.next();
                            break;
                        }
                        if t.kind == TokKind::Comma {
                            self.next();
                            continue;
                        }
                        let first_lit = self.parse_literal()?;
                        if let Some(next_t) = self.peek() {
                            if next_t.kind == TokKind::DotDot {
                                self.next();
                                let second_lit = self.parse_literal()?;
                                items.push(SetItem::Range(first_lit, second_lit));
                                continue;
                            }
                        }
                        items.push(SetItem::Single(first_lit));
                    }
                    return Ok(FilterExpr::InSet { lhs, items });
                }
                _ => {}
            }
        }

        // Standalone operand -> existence check or non-zero bitwise AND
        match lhs {
            Operand::Field(fref) => Ok(FilterExpr::Exists(fref)),
            Operand::BitwiseAnd(inner, mask) => Ok(FilterExpr::Compare {
                lhs: Operand::BitwiseAnd(inner, mask),
                op: CmpOp::BitwiseAndNonZero,
                rhs: Operand::Literal(LiteralVal::Uint(0)),
            }),
            other => Err(FilterDiagnostic {
                span: (0, self.source.len()),
                message: format!("Standalone literal or function '{other:?}' requires a comparison operator"),
                suggestions: Vec::new(),
            }),
        }
    }

    fn parse_operand(&mut self, is_lhs: bool) -> Result<Operand, FilterDiagnostic> {
        let tok = self.next().ok_or_else(|| FilterDiagnostic {
            span: (self.source.len(), self.source.len()),
            message: "Unexpected end of filter expression".to_string(),
            suggestions: Vec::new(),
        })?;

        if tok.kind == TokKind::StringLit {
            return Ok(Operand::Literal(LiteralVal::Str(tok.raw.clone())));
        }

        if tok.kind != TokKind::Ident {
            return Err(FilterDiagnostic {
                span: tok.span,
                message: format!("Expected field or value, found '{}'", tok.raw),
                suggestions: Vec::new(),
            });
        }

        // Check for built-in function call `len(...)`, `count(...)`, `upper(...)`, `lower(...)`, `string(...)`
        if let Some(next_tok) = self.peek() {
            if next_tok.kind == TokKind::LParen {
                let func = match tok.raw.to_ascii_lowercase().as_str() {
                    "len" => Some(FilterFunc::Len),
                    "count" => Some(FilterFunc::Count),
                    "upper" => Some(FilterFunc::Upper),
                    "lower" => Some(FilterFunc::Lower),
                    "string" => Some(FilterFunc::String),
                    _ => None,
                };
                if let Some(fn_kind) = func {
                    self.next(); // consume '('
                    let fref = self.parse_field_ref_from_next()?;
                    match self.next() {
                        Some(close) if close.kind == TokKind::RParen => {
                            return Ok(Operand::FuncCall(fn_kind, fref));
                        }
                        _ => {
                            return Err(FilterDiagnostic {
                                span: tok.span,
                                message: "Expected ')' after function argument".to_string(),
                                suggestions: Vec::new(),
                            });
                        }
                    }
                }
            }
        }

        // If on the LHS (or if it's a known field/alias in the registry), parse as FieldRef
        let is_known_field = is_known_field_or_alias(&tok.raw, self.registry);
        if is_lhs || is_known_field {
            if is_lhs && !is_known_field {
                if let Some(reg) = self.registry {
                    return Err(FilterDiagnostic {
                        span: tok.span,
                        message: format!("Unknown protocol or field '{}'", tok.raw),
                        suggestions: reg.did_you_mean(&tok.raw, 3),
                    });
                }
            }
            let fref = self.finish_field_ref(tok)?;
            let base = Operand::Field(fref);
            // Check for bitwise AND `& mask`
            if let Some(amp) = self.peek() {
                if amp.kind == TokKind::Amp {
                    self.next();
                    let mask_lit = self.parse_literal()?;
                    let mask_u64 = match mask_lit {
                        LiteralVal::Uint(u) => u,
                        LiteralVal::Int(i) => i as u64,
                        _ => 0,
                    };
                    return Ok(Operand::BitwiseAnd(Box::new(base), mask_u64));
                }
            }
            return Ok(base);
        }

        // Otherwise parse as literal value
        let lit = parse_literal_token(tok)?;
        Ok(Operand::Literal(lit))
    }

    fn parse_field_ref_from_next(&mut self) -> Result<FieldRef, FilterDiagnostic> {
        let tok = self.next().ok_or_else(|| FilterDiagnostic {
            span: (self.source.len(), self.source.len()),
            message: "Expected field name".to_string(),
            suggestions: Vec::new(),
        })?;
        if let Some(reg) = self.registry {
            if !is_known_field_or_alias(&tok.raw, Some(reg)) {
                return Err(FilterDiagnostic {
                    span: tok.span,
                    message: format!("Unknown protocol or field '{}'", tok.raw),
                    suggestions: reg.did_you_mean(&tok.raw, 3),
                });
            }
        }
        self.finish_field_ref(tok)
    }

    fn finish_field_ref(&mut self, ident_tok: &Token) -> Result<FieldRef, FilterDiagnostic> {
        let mut layer = None;
        let mut slice = None;

        if let Some(t) = self.peek() {
            if t.kind == TokKind::Hash {
                self.next();
                let num_tok = self.next().ok_or_else(|| FilterDiagnostic {
                    span: ident_tok.span,
                    message: "Expected layer index after '#'".to_string(),
                    suggestions: Vec::new(),
                })?;
                let idx = num_tok.raw.parse::<usize>().map_err(|_| FilterDiagnostic {
                    span: num_tok.span,
                    message: format!("Invalid layer index '{}'", num_tok.raw),
                    suggestions: Vec::new(),
                })?;
                layer = Some(idx);
            }
        }

        if let Some(t) = self.peek() {
            if t.kind == TokKind::LBracket {
                self.next();
                let spec_tok = self.next().ok_or_else(|| FilterDiagnostic {
                    span: ident_tok.span,
                    message: "Expected slice specification inside '[...]'".to_string(),
                    suggestions: Vec::new(),
                })?;
                // Support `[0:3]` (single token containing `:`), `[0..2]` (DotDot), or `[0]`
                if let Some((off_s, len_s)) = spec_tok.raw.split_once(':') {
                    let offset = off_s.parse::<usize>().unwrap_or(0);
                    let len = len_s.parse::<usize>().unwrap_or(1);
                    slice = Some(SliceSpec::OffsetLen { offset, len });
                } else if let Some(next_t) = self.peek() {
                    if next_t.kind == TokKind::Colon {
                        self.next();
                        let len_tok = self.next().ok_or_else(|| FilterDiagnostic {
                            span: spec_tok.span,
                            message: "Expected length after ':'".to_string(),
                            suggestions: Vec::new(),
                        })?;
                        let offset = spec_tok.raw.parse::<usize>().unwrap_or(0);
                        let len = len_tok.raw.parse::<usize>().unwrap_or(1);
                        slice = Some(SliceSpec::OffsetLen { offset, len });
                    } else if next_t.kind == TokKind::DotDot {
                        self.next();
                        let end_tok = self.next().ok_or_else(|| FilterDiagnostic {
                            span: spec_tok.span,
                            message: "Expected end index after '..'".to_string(),
                            suggestions: Vec::new(),
                        })?;
                        let start = spec_tok.raw.parse::<usize>().unwrap_or(0);
                        let end_inclusive = end_tok.raw.parse::<usize>().unwrap_or(start);
                        slice = Some(SliceSpec::Range {
                            start,
                            end_inclusive,
                        });
                    } else {
                        let idx = spec_tok.raw.parse::<usize>().unwrap_or(0);
                        slice = Some(SliceSpec::Index(idx));
                    }
                }
                match self.next() {
                    Some(close) if close.kind == TokKind::RBracket => {}
                    _ => {
                        return Err(FilterDiagnostic {
                            span: ident_tok.span,
                            message: "Expected closing ']' for slice".to_string(),
                            suggestions: Vec::new(),
                        });
                    }
                }
            }
        }

        Ok(FieldRef {
            abbrev: ident_tok.raw.clone(),
            layer,
            slice,
        })
    }

    fn parse_literal(&mut self) -> Result<LiteralVal, FilterDiagnostic> {
        let tok = self.next().ok_or_else(|| FilterDiagnostic {
            span: (self.source.len(), self.source.len()),
            message: "Expected literal value".to_string(),
            suggestions: Vec::new(),
        })?;
        if tok.kind == TokKind::StringLit {
            return Ok(LiteralVal::Str(tok.raw.clone()));
        }
        parse_literal_token(tok)
    }
}

fn is_known_field_or_alias(abbrev: &str, registry: Option<&Registry>) -> bool {
    if matches!(
        abbrev,
        "ip.addr" | "ipv6.addr" | "tcp.port" | "udp.port" | "eth.addr"
    ) {
        return true;
    }
    match registry {
        Some(reg) => {
            reg.field_by_abbrev(abbrev).is_some() || reg.protocol_by_filter(abbrev).is_some()
        }
        None => {
            // When no registry is supplied, treat dotted identifiers or common protocol names as fields
            abbrev.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && !matches!(abbrev, "true" | "false" | "True" | "False")
        }
    }
}

fn parse_literal_token(tok: &Token) -> Result<LiteralVal, FilterDiagnostic> {
    let s = tok.raw.as_str();
    match s.to_ascii_lowercase().as_str() {
        "true" => return Ok(LiteralVal::Bool(true)),
        "false" => return Ok(LiteralVal::Bool(false)),
        _ => {}
    }

    // IPv4 CIDR (e.g., `10.0.0.0/8`)
    if let Some((ip_part, prefix_part)) = s.split_once('/') {
        if let (Ok(ip), Ok(prefix)) = (ip_part.parse::<Ipv4Addr>(), prefix_part.parse::<u32>()) {
            if prefix <= 32 {
                let mask = if prefix == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix)
                };
                let net = u32::from(ip) & mask;
                return Ok(LiteralVal::Ipv4Cidr { net, mask });
            }
        }
    }

    // IPv4 address
    if let Ok(ipv4) = s.parse::<Ipv4Addr>() {
        return Ok(LiteralVal::Ipv4(ipv4.octets()));
    }

    // Hex / Binary / Decimal integer
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if let Ok(v) = u64::from_str_radix(hex, 16) {
            return Ok(LiteralVal::Uint(v));
        }
    }
    if let Some(bin) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        if let Ok(v) = u64::from_str_radix(bin, 2) {
            return Ok(LiteralVal::Uint(v));
        }
    }
    if let Ok(v) = s.parse::<u64>() {
        return Ok(LiteralVal::Uint(v));
    }
    if let Ok(v) = s.parse::<i64>() {
        return Ok(LiteralVal::Int(v));
    }
    if s.contains('.') {
        if let Ok(f) = s.parse::<f64>() {
            if f.is_finite() {
                return Ok(LiteralVal::Float(f));
            }
        }
    }

    // Colon-separated hex bytes or MAC address (`00:11:22` or `aa:bb:cc:dd:ee:ff`)
    if s.contains(':') && s.split(':').all(|part| part.len() == 2 && u8::from_str_radix(part, 16).is_ok()) {
        let bytes: Vec<u8> = s
            .split(':')
            .filter_map(|p| u8::from_str_radix(p, 16).ok())
            .collect();
        return Ok(LiteralVal::Bytes(bytes));
    }

    // IPv6 address
    if let Ok(ipv6) = s.parse::<Ipv6Addr>() {
        return Ok(LiteralVal::Ipv6(ipv6.octets()));
    }

    // Fallback to string literal for bare words on RHS (e.g., `dns.qry.name == example.com`)
    Ok(LiteralVal::Str(s.to_string()))
}

fn expand_aliases(abbrev: &str) -> Vec<&str> {
    match abbrev {
        "ip.addr" => vec!["ip.src", "ip.dst"],
        "ipv6.addr" => vec!["ipv6.src", "ipv6.dst"],
        "tcp.port" => vec!["tcp.srcport", "tcp.dstport"],
        "udp.port" => vec!["udp.srcport", "udp.dstport"],
        "eth.addr" => vec!["eth.src", "eth.dst"],
        _ => vec![abbrev],
    }
}

fn collect_field_values(pkt: &DissectedPacket, fref: &FieldRef) -> Vec<FieldValue> {
    let mut vals = Vec::new();
    for target in expand_aliases(&fref.abbrev) {
        if let Some(layer_idx) = fref.layer {
            if let Some(node) = pkt.tree.by_abbrev_layer(target, layer_idx) {
                if let Some(v) = apply_slice(&node.value, fref.slice) {
                    vals.push(v);
                }
            }
        } else {
            for node in pkt.tree.by_abbrev(target) {
                if let Some(v) = apply_slice(&node.value, fref.slice) {
                    vals.push(v);
                }
            }
        }
    }
    vals
}

fn apply_slice(val: &FieldValue, slice: Option<SliceSpec>) -> Option<FieldValue> {
    let Some(spec) = slice else {
        return Some(val.clone());
    };
    if let FieldValue::Str(s) = val {
        let bytes = s.as_bytes();
        let sub = slice_bytes(bytes, spec)?;
        return Some(FieldValue::Str(String::from_utf8_lossy(sub).to_string()));
    }
    let bytes = val.as_bytes()?;
    let sub = slice_bytes(bytes, spec)?;
    Some(FieldValue::Bytes(sub.to_vec()))
}

fn slice_bytes(bytes: &[u8], spec: SliceSpec) -> Option<&[u8]> {
    match spec {
        SliceSpec::Index(i) => bytes.get(i..i + 1),
        SliceSpec::OffsetLen { offset, len } => bytes.get(offset..offset.saturating_add(len)),
        SliceSpec::Range {
            start,
            end_inclusive,
        } => {
            if end_inclusive < start {
                None
            } else {
                bytes.get(start..=end_inclusive)
            }
        }
    }
}

fn eval_operand(op: &Operand, pkt: &DissectedPacket) -> Vec<FieldValue> {
    match op {
        Operand::Field(fref) => collect_field_values(pkt, fref),
        Operand::FuncCall(func, fref) => {
            let vals = collect_field_values(pkt, fref);
            match func {
                FilterFunc::Count => vec![FieldValue::U64(vals.len() as u64)],
                FilterFunc::Len => vals
                    .into_iter()
                    .map(|v| FieldValue::U64(v.value_len() as u64))
                    .collect(),
                FilterFunc::Upper => vals
                    .into_iter()
                    .map(|v| FieldValue::Str(v.display_value().to_ascii_uppercase()))
                    .collect(),
                FilterFunc::Lower => vals
                    .into_iter()
                    .map(|v| FieldValue::Str(v.display_value().to_ascii_lowercase()))
                    .collect(),
                FilterFunc::String => vals
                    .into_iter()
                    .map(|v| FieldValue::Str(v.display_value()))
                    .collect(),
            }
        }
        Operand::BitwiseAnd(inner, mask) => eval_operand(inner, pkt)
            .into_iter()
            .filter_map(|v| v.as_u64().map(|u| FieldValue::U64(u & *mask)))
            .collect(),
        Operand::Literal(lit) => vec![literal_to_field_value(lit)],
    }
}

fn literal_to_field_value(lit: &LiteralVal) -> FieldValue {
    match lit {
        LiteralVal::Bool(b) => FieldValue::Bool(*b),
        LiteralVal::Int(i) => FieldValue::I64(*i),
        LiteralVal::Uint(u) => FieldValue::U64(*u),
        LiteralVal::Float(f) => FieldValue::F64(*f),
        LiteralVal::Str(s) => FieldValue::Str(s.clone()),
        LiteralVal::Ipv4(ip) => FieldValue::Ipv4(*ip),
        LiteralVal::Ipv4Cidr { net, .. } => FieldValue::Ipv4(net.to_be_bytes()),
        LiteralVal::Ipv6(ip) => FieldValue::Ipv6(*ip),
        LiteralVal::Bytes(b) => FieldValue::Bytes(b.clone()),
    }
}

fn eval_expr(expr: &FilterExpr, pkt: &DissectedPacket) -> bool {
    match expr {
        FilterExpr::MatchAll => true,
        FilterExpr::Exists(fref) => {
            for target in expand_aliases(&fref.abbrev) {
                if pkt.tree.has_field_or_protocol(target) {
                    return true;
                }
            }
            false
        }
        FilterExpr::Not(inner) => !eval_expr(inner, pkt),
        FilterExpr::And(a, b) => eval_expr(a, pkt) && eval_expr(b, pkt),
        FilterExpr::Or(a, b) => eval_expr(a, pkt) || eval_expr(b, pkt),
        FilterExpr::Xor(a, b) => eval_expr(a, pkt) ^ eval_expr(b, pkt),
        FilterExpr::Compare { lhs, op, rhs } => {
            let lhs_vals = eval_operand(lhs, pkt);
            if lhs_vals.is_empty() {
                return false;
            }
            if *op == CmpOp::BitwiseAndNonZero {
                return lhs_vals.iter().any(|v| v.as_u64().unwrap_or(0) != 0);
            }
            // Special handling for IPv4 CIDR on RHS
            if let Operand::Literal(LiteralVal::Ipv4Cidr { net, mask }) = rhs {
                return lhs_vals.iter().any(|lv| {
                    if let FieldValue::Ipv4(ip) = lv {
                        let ip_u32 = u32::from_be_bytes(*ip);
                        let matched = (ip_u32 & *mask) == *net;
                        match op {
                            CmpOp::Eq => matched,
                            CmpOp::Ne => !matched,
                            _ => false,
                        }
                    } else {
                        false
                    }
                });
            }
            let rhs_vals = eval_operand(rhs, pkt);
            for lv in &lhs_vals {
                for rv in &rhs_vals {
                    if compare_values(lv, *op, rv) {
                        return true;
                    }
                }
            }
            false
        }
        FilterExpr::Matches { lhs, regex, .. } => {
            let lhs_vals = eval_operand(lhs, pkt);
            lhs_vals.iter().any(|v| regex.is_match(&v.display_value()))
        }
        FilterExpr::InSet { lhs, items } => {
            let lhs_vals = eval_operand(lhs, pkt);
            for lv in &lhs_vals {
                for item in items {
                    match item {
                        SetItem::Single(lit) => {
                            let rv = literal_to_field_value(lit);
                            if compare_values(lv, CmpOp::Eq, &rv) {
                                return true;
                            }
                        }
                        SetItem::Range(lo, hi) => {
                            let lo_v = literal_to_field_value(lo);
                            let hi_v = literal_to_field_value(hi);
                            if compare_values(lv, CmpOp::Ge, &lo_v)
                                && compare_values(lv, CmpOp::Le, &hi_v)
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            false
        }
    }
}

fn compare_values(lv: &FieldValue, op: CmpOp, rv: &FieldValue) -> bool {
    if op == CmpOp::Contains {
        if let (Some(lb), Some(rb)) = (lv.as_bytes(), rv.as_bytes()) {
            if rb.is_empty() {
                return true;
            }
            if lb.windows(rb.len()).any(|w| w == rb) {
                return true;
            }
        }
        return lv.display_value().contains(&rv.display_value());
    }

    // Numeric comparison
    if let (Some(lu), Some(ru)) = (lv.as_u64(), rv.as_u64()) {
        return match op {
            CmpOp::Eq => lu == ru,
            CmpOp::Ne => lu != ru,
            CmpOp::Gt => lu > ru,
            CmpOp::Lt => lu < ru,
            CmpOp::Ge => lu >= ru,
            CmpOp::Le => lu <= ru,
            _ => false,
        };
    }
    if let (Some(lf), Some(rf)) = (lv.as_f64(), rv.as_f64()) {
        return match op {
            CmpOp::Eq => (lf - rf).abs() < 1e-9,
            CmpOp::Ne => (lf - rf).abs() >= 1e-9,
            CmpOp::Gt => lf > rf,
            CmpOp::Lt => lf < rf,
            CmpOp::Ge => lf >= rf,
            CmpOp::Le => lf <= rf,
            _ => false,
        };
    }

    // Byte / Address comparison
    if let (Some(lb), Some(rb)) = (lv.as_bytes(), rv.as_bytes()) {
        return match op {
            CmpOp::Eq => lb == rb,
            CmpOp::Ne => lb != rb,
            CmpOp::Gt => lb > rb,
            CmpOp::Lt => lb < rb,
            CmpOp::Ge => lb >= rb,
            CmpOp::Le => lb <= rb,
            _ => false,
        };
    }

    let ls = lv.display_value();
    let rs = rv.display_value();
    match op {
        CmpOp::Eq => ls == rs,
        CmpOp::Ne => ls != rs,
        CmpOp::Gt => ls > rs,
        CmpOp::Lt => ls < rs,
        CmpOp::Ge => ls >= rs,
        CmpOp::Le => ls <= rs,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mash_core::{ByteRange, FieldId, FieldTree, FieldType, PacketSummary, ProtocolId};

    fn sample_dissected() -> DissectedPacket {
        let mut tree = FieldTree::new();
        tree.add_protocol_in_frame("eth");
        tree.add_protocol_in_frame("ip");
        tree.add_protocol_in_frame("tcp");
        tree.add_protocol_in_frame("http");
        tree.add_node(
            None,
            FieldId(1),
            ProtocolId(1),
            "eth.src",
            "Source",
            "",
            FieldType::MacAddr,
            FieldValue::Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            ByteRange::new(6, 12),
            false,
        );
        tree.add_node(
            None,
            FieldId(2),
            ProtocolId(2),
            "ip.src",
            "Source Address",
            "",
            FieldType::Ipv4,
            FieldValue::Ipv4([10, 1, 2, 3]),
            ByteRange::new(26, 30),
            false,
        );
        tree.add_node(
            None,
            FieldId(3),
            ProtocolId(2),
            "ip.dst",
            "Destination Address",
            "",
            FieldType::Ipv4,
            FieldValue::Ipv4([93, 184, 216, 34]),
            ByteRange::new(30, 34),
            false,
        );
        tree.add_node(
            None,
            FieldId(4),
            ProtocolId(3),
            "tcp.srcport",
            "Source Port",
            "",
            FieldType::Uint16,
            FieldValue::U64(54321),
            ByteRange::new(34, 36),
            false,
        );
        tree.add_node(
            None,
            FieldId(5),
            ProtocolId(3),
            "tcp.dstport",
            "Destination Port",
            "",
            FieldType::Uint16,
            FieldValue::U64(443),
            ByteRange::new(36, 38),
            false,
        );
        tree.add_node(
            None,
            FieldId(6),
            ProtocolId(3),
            "tcp.flags",
            "Flags",
            "",
            FieldType::Uint16,
            FieldValue::U64(0x018),
            ByteRange::new(46, 48),
            false,
        );
        tree.add_node(
            None,
            FieldId(7),
            ProtocolId(4),
            "http.host",
            "Host",
            "",
            FieldType::String,
            FieldValue::Str("api.example.com".to_string()),
            ByteRange::new(54, 70),
            false,
        );
        DissectedPacket {
            summary: PacketSummary::default(),
            tree,
        }
    }

    #[test]
    fn filter_evaluates_aliases_cidr_sets_slices_functions_and_regex() {
        let pkt = sample_dissected();

        // Protocol existence & logical operators
        let f1 = CompiledFilter::compile("tcp && http && !dns", None).unwrap();
        assert!(f1.matches(&pkt));

        // Alias `ip.addr` + CIDR subnet `10.0.0.0/8`
        let f2 = CompiledFilter::compile("ip.addr == 10.0.0.0/8", None).unwrap();
        assert!(f2.matches(&pkt));

        // Alias `tcp.port` + `in {80, 443, 8000..8080}`
        let f3 = CompiledFilter::compile("tcp.port in {80, 443, 8000..8080}", None).unwrap();
        assert!(f3.matches(&pkt));

        // Byte slice `eth.src[0:3] == 00:11:22`
        let f4 = CompiledFilter::compile("eth.src[0:3] == 00:11:22", None).unwrap();
        assert!(f4.matches(&pkt));

        // Bitwise AND `tcp.flags & 0x08`
        let f5 = CompiledFilter::compile("tcp.flags & 0x08", None).unwrap();
        assert!(f5.matches(&pkt));

        // Built-in functions `lower()`, `len()`, `count()` and `matches` regex
        let f6 = CompiledFilter::compile(
            "lower(http.host) contains \"example\" && len(http.host) == 15 && count(ip.src) == 1 && http.host matches \"^api\\\\..*\\\\.com$\"",
            None,
        )
        .unwrap();
        assert!(f6.matches(&pkt));
    }

    #[test]
    fn filter_diagnostics_report_span_and_did_you_mean() {
        let mut reg = Registry::new();
        let pid = reg.register_protocol("IPv4", "IPv4", "ip").unwrap();
        reg.register_field(pid, "ip.src", "Source", FieldType::Ipv4, "")
            .unwrap();

        let err = CompiledFilter::compile("ip.scr == 10.0.0.1", Some(&reg)).unwrap_err();
        assert_eq!(err.span, (0, 6));
        assert!(err.suggestions.contains(&"ip.src".to_string()));
    }
}
