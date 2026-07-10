//! Symbolic byte-count expressions used by the heap-size analyser.
//!
//! The analyser characterises both the allocated size of a heap buffer
//! and the number of bytes a string-write call (sprintf, strcpy, ...)
//! emits into it. Both sides are expressed as [`SizeExpr`] values so
//! they can be compared symbolically — for example,
//! `strlen(name) + 1` is detectably smaller than
//! `strlen(name) + strlen(prefix) + 2`, which is the canonical
//! under-sized-allocation-plus-sprintf overflow shape this module
//! exists to catch.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;

use tree_sitter::Node;

/// A symbolic byte-count expression. Each variant represents the
/// number of bytes a buffer holds, or that a source-write produces.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SizeExpr {
    /// A compile-time byte count.
    Constant(u64),
    /// `strlen(name)` where `name` is a source-level identifier.
    StrlenOf(String),
    /// A sum of two or more sub-terms. Constructed only via
    /// [`SizeExpr::add`], which maintains these invariants:
    ///
    /// * no nested `Sum` inside (sums are always flat),
    /// * no `Unknown` inside (additions involving `Unknown` short-circuit),
    /// * at most one `Constant` term, and it appears last,
    /// * non-constant terms are sorted by their `Display` form so two
    ///   `Sum`s with the same multiset of terms compare equal.
    Sum(Vec<SizeExpr>),
    /// A size the analyser could not characterise. Any arithmetic
    /// involving `Unknown` is `Unknown` — this short-circuits
    /// downstream reasoning rather than producing false comparisons.
    Unknown,
}

impl SizeExpr {
    /// Return `self + extra` where `extra` is a literal byte count.
    /// Convenience for callers that need to add a constant (e.g. the
    /// NUL terminator implicitly written by sprintf).
    pub fn plus_constant(self, extra: u64) -> Self {
        self.add(SizeExpr::Constant(extra))
    }

    /// Symbolic addition.
    ///
    /// Folds constants, flattens nested sums, and returns the result
    /// in canonical form (see [`SizeExpr::Sum`] for invariants).
    // Inherent symbolic fold over SizeExpr, not std::ops::Add on values.
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: Self) -> Self {
        if matches!(self, SizeExpr::Unknown) || matches!(other, SizeExpr::Unknown) {
            return SizeExpr::Unknown;
        }

        let mut constant_sum: u64 = 0;
        let mut symbolic_terms: Vec<SizeExpr> = Vec::new();
        flatten_into(self, &mut constant_sum, &mut symbolic_terms);
        flatten_into(other, &mut constant_sum, &mut symbolic_terms);

        symbolic_terms.sort_by_key(|left| left.to_string());
        if constant_sum > 0 {
            symbolic_terms.push(SizeExpr::Constant(constant_sum));
        }
        match symbolic_terms.len() {
            0 => SizeExpr::Constant(0),
            1 => symbolic_terms.pop().expect("len checked"),
            _ => SizeExpr::Sum(symbolic_terms),
        }
    }
}

/// A single string-writing call: which destination it writes into and
/// how many bytes the analyser believes it produces. Used to compare
/// against the allocation map returned by [`collect_allocation_sizes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteSite {
    /// Source text of the destination — an identifier or field
    /// reference whose allocation size the analyser is expected to
    /// know from a prior allocator call.
    pub destination: String,
    /// Number of bytes the call writes, including any implicit NUL.
    /// `Unknown` when the analyser cannot bound the write.
    pub write_size: SizeExpr,
    /// 1-indexed line of the call expression. Used when projecting a
    /// detected overflow into a SecurityFinding.
    pub line: usize,
    /// 1-indexed column of the call expression.
    pub column: usize,
    /// 1-indexed end line of the call expression.
    pub end_line: usize,
    /// 1-indexed end column of the call expression.
    pub end_column: usize,
    /// Verbatim source text of the call expression.
    pub snippet: String,
}

/// A buffer-overflow detection: a [`WriteSite`] whose write size
/// provably exceeds the allocation associated with its destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapOverflowFinding {
    /// Source-text key of the buffer (e.g. `buf`, `ctx->buf`).
    pub destination: String,
    /// Size the allocator produced.
    pub allocation_size: SizeExpr,
    /// Size the write site emits.
    pub write_size: SizeExpr,
    /// File the finding is reported against.
    pub file_path: String,
    /// 1-indexed line of the offending write call.
    pub line: usize,
    /// 1-indexed column of the offending write call.
    pub column: usize,
    /// 1-indexed end line of the offending write call.
    pub end_line: usize,
    /// 1-indexed end column of the offending write call.
    pub end_column: usize,
    /// Source text of the offending write call.
    pub snippet: String,
}

/// Walk a C function body and return one [`WriteSite`] per modeled
/// string-writing call. Currently recognises `sprintf` and `vsprintf`;
/// the str/mem family is added in a later patch.
pub fn collect_write_sites(function_body: Node<'_>, source: &str) -> Vec<WriteSite> {
    let mut out = Vec::new();
    collect_writes_into(function_body, source, &mut out);
    out
}

fn collect_writes_into(node: Node<'_>, source: &str, out: &mut Vec<WriteSite>) {
    if node.kind() == "call_expression" {
        if let Some(write_site) = recognise_write_call(node, source) {
            out.push(write_site);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_writes_into(child, source, out);
    }
}

/// Recognise a string-writing call and return its [`WriteSite`].
///
/// The destination must be a plain identifier or field reference; if
/// it isn't we have no stable name to compare against the allocation
/// map and we skip the call.
///
/// Modelled calls (all write sizes include any implicit NUL the C
/// library writes — i.e. the total buffer footprint, so the rule can
/// compare a single `write_size` against a single allocation size):
///
/// * `sprintf(dst, fmt, …)` → `write_size_of_format(fmt, args) + 1`
/// * `vsprintf(dst, fmt, va_list)` → `Unknown` (opaque va_list)
/// * `strcpy(dst, src)` → `string_source_size(src) + 1`
/// * `strncpy(dst, src, n)` → `parse_size_expression(n)` (no NUL guarantee)
/// * `strcat(dst, src)` → `StrlenOf(dst) + StrlenOf(src) + 1` (total
///   footprint after the append; the buffer must hold this many bytes)
/// * `memcpy(dst, src, n)` → `parse_size_expression(n)`
/// * `memmove(dst, src, n)` → `parse_size_expression(n)`
/// * `memset(dst, c, n)` → `parse_size_expression(n)`
fn recognise_write_call(call: Node<'_>, source: &str) -> Option<WriteSite> {
    let function_name = call
        .child_by_field_name("function")?
        .utf8_text(source.as_bytes())
        .ok()?;

    let arguments = call.child_by_field_name("arguments")?;
    let argument_nodes: Vec<Node<'_>> = (0..(arguments.named_child_count() as u32))
        .filter_map(|idx| arguments.named_child(idx))
        .collect();
    if argument_nodes.is_empty() {
        return None;
    }

    let destination = extract_simple_destination(argument_nodes[0], source)?;

    let write_size = match function_name {
        "sprintf" => {
            if argument_nodes.len() < 2 {
                return None;
            }
            let format = extract_string_literal_content(argument_nodes[1], source)?;
            let argument_names: Vec<String> = argument_nodes[2..]
                .iter()
                .map(|node| node.utf8_text(source.as_bytes()).unwrap_or("").to_string())
                .collect();
            write_size_of_format(&format, &argument_names).plus_constant(1)
        }
        "vsprintf" => SizeExpr::Unknown,
        "strcpy" => {
            if argument_nodes.len() < 2 {
                return None;
            }
            string_source_size(argument_nodes[1], source).plus_constant(1)
        }
        "strncpy" => {
            if argument_nodes.len() < 3 {
                return None;
            }
            parse_size_expression(argument_nodes[2], source)
        }
        "strcat" => {
            if argument_nodes.len() < 2 {
                return None;
            }
            // strcat writes at offset strlen(dst), so the buffer must
            // hold strlen(dst) + strlen(src) + 1. Encode the required
            // footprint as the write size so the overflow rule needs
            // only one comparison against the allocation size.
            let dst_footprint = string_source_size(argument_nodes[0], source);
            let src_footprint = string_source_size(argument_nodes[1], source);
            dst_footprint.add(src_footprint).plus_constant(1)
        }
        "memcpy" | "memmove" | "memset" => {
            if argument_nodes.len() < 3 {
                return None;
            }
            parse_size_expression(argument_nodes[2], source)
        }
        _ => return None,
    };

    let start = call.start_position();
    let end = call.end_position();
    let snippet = call
        .utf8_text(source.as_bytes())
        .ok()
        .unwrap_or("")
        .to_string();
    Some(WriteSite {
        destination,
        write_size,
        line: start.row + 1,
        column: start.column + 1,
        end_line: end.row + 1,
        end_column: end.column + 1,
        snippet,
    })
}

/// Compare a write size to an allocation size and return `true` iff
/// the write *provably* exceeds the allocation across every
/// substitution of the symbolic terms.
///
/// The decision procedure is intentionally conservative: it only fires
/// when the write side dominates the allocation side both in its
/// constant component **and** in its multiset of `StrlenOf` terms.
/// Anything involving `Unknown` short-circuits to `false`.
///
/// Examples (all real overflow shapes from the security report):
///
/// * `Constant(40)` vs `Constant(32)` → `true` (literal-vs-literal).
/// * `StrlenOf(name) + 2` vs `StrlenOf(name) + 1` → `true` (extra NUL).
/// * `StrlenOf(name) + StrlenOf(prefix) + 2` vs `StrlenOf(name) + 1` →
///   `true` (the canonical asprintf-then-sprintf shape: the write's
///   constant exceeds the allocation's and adds a non-negative term).
/// * `Constant(5)` vs `StrlenOf(name) + 1` → `false` (the strlen term
///   could swallow the difference; we cannot prove overflow).
pub fn write_exceeds_allocation(write: &SizeExpr, allocation: &SizeExpr) -> bool {
    if matches!(write, SizeExpr::Unknown) || matches!(allocation, SizeExpr::Unknown) {
        return false;
    }
    let (write_strlens, write_constant) = decompose_size(write);
    let (allocation_strlens, allocation_constant) = decompose_size(allocation);

    if !multiset_contains_all(&write_strlens, &allocation_strlens) {
        return false;
    }
    write_constant > allocation_constant
}

/// Pair an allocation map against a write-site list and return one
/// [`HeapOverflowFinding`] per write whose size provably exceeds its
/// destination's allocation. The `file_path` is propagated verbatim
/// into every emitted finding.
pub fn detect_overflows(
    allocations: &HashMap<String, SizeExpr>,
    write_sites: &[WriteSite],
    file_path: &str,
) -> Vec<HeapOverflowFinding> {
    let mut findings = Vec::new();
    for site in write_sites {
        let Some(allocation) = allocations.get(&site.destination) else {
            continue;
        };
        if !write_exceeds_allocation(&site.write_size, allocation) {
            continue;
        }
        findings.push(HeapOverflowFinding {
            destination: site.destination.clone(),
            allocation_size: allocation.clone(),
            write_size: site.write_size.clone(),
            file_path: file_path.to_string(),
            line: site.line,
            column: site.column,
            end_line: site.end_line,
            end_column: site.end_column,
            snippet: site.snippet.clone(),
        });
    }
    findings
}

/// A literal-only arithmetic expression in an allocator argument that
/// would wrap u64 at runtime, producing a smaller-than-intended
/// allocation. The canonical CWE-680 shape, but limited to the
/// fully-provable constant case — non-literal operands are out of
/// scope (see CWE-680-002 for the sizeof-multiplication shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstantOverflowFinding {
    /// Allocator function name (`malloc`, `calloc`, `realloc`).
    pub allocator: String,
    /// Source text of the offending arithmetic expression.
    pub expression: String,
    /// Left operand value as written in source.
    pub left_value: u64,
    /// Right operand value as written in source.
    pub right_value: u64,
    /// Arithmetic operator, `*` or `+`.
    pub operator: &'static str,
    /// File the finding is reported against.
    pub file_path: String,
    /// 1-indexed line of the allocator call.
    pub line: usize,
    /// 1-indexed column of the allocator call.
    pub column: usize,
    /// 1-indexed end line of the allocator call.
    pub end_line: usize,
    /// 1-indexed end column of the allocator call.
    pub end_column: usize,
    /// Source text of the full allocator call.
    pub snippet: String,
}

/// Scan `code` for CWE-680 constant-arithmetic wraparound in
/// allocator size arguments. Only fires when every operand is a
/// literal — there is no value-range analysis, no taint, and no
/// inter-procedural reasoning. A negative result does **not** prove
/// the file is free of integer-overflow-to-buffer bugs.
pub fn scan_constant_overflows(code: &str, file_path: &str) -> Vec<ConstantOverflowFinding> {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(code, None) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression" {
            if let Some(finding) = recognise_constant_overflow(node, code, file_path) {
                findings.push(finding);
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    findings
}

fn recognise_constant_overflow(
    call: Node<'_>,
    source: &str,
    file_path: &str,
) -> Option<ConstantOverflowFinding> {
    let function_name = call
        .child_by_field_name("function")?
        .utf8_text(source.as_bytes())
        .ok()?;
    let arguments = call.child_by_field_name("arguments")?;
    let argument_nodes: Vec<Node<'_>> = (0..(arguments.named_child_count() as u32))
        .filter_map(|idx| arguments.named_child(idx))
        .collect();

    let candidate = match function_name {
        "malloc" => argument_nodes.first().copied().and_then(|arg| {
            evaluate_for_overflow(arg, source).map(|(op, l, r)| {
                let expression = arg.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                (op, l, r, expression)
            })
        }),
        "realloc" => argument_nodes.get(1).copied().and_then(|arg| {
            evaluate_for_overflow(arg, source).map(|(op, l, r)| {
                let expression = arg.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                (op, l, r, expression)
            })
        }),
        "calloc" => {
            if argument_nodes.len() < 2 {
                return None;
            }
            let nmemb = checked_evaluate(argument_nodes[0], source)?;
            let size = checked_evaluate(argument_nodes[1], source)?;
            let (nmemb, size) = match (nmemb, size) {
                (CheckedValue::Constant(a), CheckedValue::Constant(b)) => (a, b),
                _ => return None,
            };
            if nmemb.checked_mul(size).is_some() {
                return None;
            }
            let nmemb_text = argument_nodes[0]
                .utf8_text(source.as_bytes())
                .unwrap_or("")
                .to_string();
            let size_text = argument_nodes[1]
                .utf8_text(source.as_bytes())
                .unwrap_or("")
                .to_string();
            Some(("*", nmemb, size, format!("{} * {}", nmemb_text, size_text)))
        }
        _ => None,
    };

    let (operator, left_value, right_value, expression) = candidate?;
    let start = call.start_position();
    let end = call.end_position();
    let snippet = call.utf8_text(source.as_bytes()).unwrap_or("").to_string();
    Some(ConstantOverflowFinding {
        allocator: function_name.to_string(),
        expression,
        left_value,
        right_value,
        operator,
        file_path: file_path.to_string(),
        line: start.row + 1,
        column: start.column + 1,
        end_line: end.row + 1,
        end_column: end.column + 1,
        snippet,
    })
}

enum CheckedValue {
    Constant(u64),
    NotConstant,
}

/// If `node` is a binary `*` or `+` whose two operands are integer
/// literals and whose computed value wraps u64, return the operator
/// and the two literal values. Otherwise `None`.
fn evaluate_for_overflow(node: Node<'_>, source: &str) -> Option<(&'static str, u64, u64)> {
    let unwrapped = unwrap_paren(node);
    if unwrapped.kind() != "binary_expression" {
        return None;
    }
    let operator = unwrapped
        .child_by_field_name("operator")
        .and_then(|child| child.utf8_text(source.as_bytes()).ok())?;
    let operator_kind: &'static str = match operator {
        "*" => "*",
        "+" => "+",
        _ => return None,
    };
    let left = unwrapped.child_by_field_name("left")?;
    let right = unwrapped.child_by_field_name("right")?;
    let CheckedValue::Constant(left_value) = checked_evaluate(left, source)? else {
        return None;
    };
    let CheckedValue::Constant(right_value) = checked_evaluate(right, source)? else {
        return None;
    };
    let wraps = match operator_kind {
        "*" => left_value.checked_mul(right_value).is_none(),
        "+" => left_value.checked_add(right_value).is_none(),
        _ => unreachable!(),
    };
    if wraps {
        Some((operator_kind, left_value, right_value))
    } else {
        None
    }
}

fn unwrap_paren(node: Node<'_>) -> Node<'_> {
    if node.kind() != "parenthesized_expression" {
        return node;
    }
    for idx in 0..(node.named_child_count() as u32) {
        if let Some(child) = node.named_child(idx) {
            return unwrap_paren(child);
        }
    }
    node
}

fn checked_evaluate(node: Node<'_>, source: &str) -> Option<CheckedValue> {
    let node = unwrap_paren(node);
    match node.kind() {
        "number_literal" => {
            let text = node.utf8_text(source.as_bytes()).ok()?;
            match parse_c_integer(text) {
                SizeExpr::Constant(value) => Some(CheckedValue::Constant(value)),
                _ => Some(CheckedValue::NotConstant),
            }
        }
        "binary_expression" => {
            // Recursive evaluation deliberately skipped: deeply nested
            // constant arithmetic is rare in real allocators and the
            // simple flat check above handles every shape we have
            // ever seen as a CWE-680 in practice.
            Some(CheckedValue::NotConstant)
        }
        _ => Some(CheckedValue::NotConstant),
    }
}

/// An allocator call with `sizeof(T)` multiplied by a non-constant
/// operand — the canonical CWE-680 exploit shape. The rule fires on
/// shape alone; it has no way to know whether the non-constant
/// operand is bounded elsewhere in the program, so it is an
/// over-approximation by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SizeofMulFinding {
    /// Allocator function name (`malloc`, `calloc`, `realloc`).
    pub allocator: String,
    /// Source text of the non-constant operand (the variable that
    /// could be attacker-controlled).
    pub variable_operand: String,
    /// Source text of the `sizeof(...)` expression.
    pub sizeof_operand: String,
    /// File the finding is reported against.
    pub file_path: String,
    /// 1-indexed line of the allocator call.
    pub line: usize,
    /// 1-indexed column of the allocator call.
    pub column: usize,
    /// 1-indexed end line of the allocator call.
    pub end_line: usize,
    /// 1-indexed end column of the allocator call.
    pub end_column: usize,
    /// Source text of the full allocator call.
    pub snippet: String,
}

/// Scan `code` for the canonical CWE-680 exploit shape:
/// `malloc(expr * sizeof(T))` or `calloc(expr, sizeof(T))` where
/// `expr` is not a compile-time constant. This shape is the most
/// common path to an integer-overflow-to-buffer bug; if `expr` is
/// attacker-controlled and large, the multiplication wraps before
/// reaching the allocator.
///
/// **Coverage caveat (for AI callers)**: this rule fires on
/// structure alone — it does not track whether `expr` is bounded by
/// a prior check, does not follow it across functions, and does not
/// inspect taint. A clean scan does NOT prove the file is free of
/// CWE-680.
pub fn scan_sizeof_multiplications(code: &str, file_path: &str) -> Vec<SizeofMulFinding> {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(code, None) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression" {
            if let Some(finding) = recognise_sizeof_mul(node, code, file_path) {
                findings.push(finding);
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    findings
}

fn recognise_sizeof_mul(call: Node<'_>, source: &str, file_path: &str) -> Option<SizeofMulFinding> {
    let function_name = call
        .child_by_field_name("function")?
        .utf8_text(source.as_bytes())
        .ok()?;
    let arguments = call.child_by_field_name("arguments")?;
    let argument_nodes: Vec<Node<'_>> = (0..(arguments.named_child_count() as u32))
        .filter_map(|idx| arguments.named_child(idx))
        .collect();

    let (sizeof_operand, variable_operand) = match function_name {
        "malloc" => {
            let size_arg = unwrap_paren(*argument_nodes.first()?);
            extract_sizeof_mul_operands(size_arg, source)?
        }
        "realloc" => {
            let size_arg = unwrap_paren(*argument_nodes.get(1)?);
            extract_sizeof_mul_operands(size_arg, source)?
        }
        "calloc" => {
            if argument_nodes.len() < 2 {
                return None;
            }
            let first = unwrap_paren(argument_nodes[0]);
            let second = unwrap_paren(argument_nodes[1]);
            // Calloc's implicit multiplication: report when one arg
            // is sizeof(...) and the other is a non-literal expression.
            match (is_sizeof(first), is_sizeof(second)) {
                (true, false) if !is_integer_literal(second) => {
                    (text_of(first, source), text_of(second, source))
                }
                (false, true) if !is_integer_literal(first) => {
                    (text_of(second, source), text_of(first, source))
                }
                _ => return None,
            }
        }
        _ => return None,
    };

    let start = call.start_position();
    let end = call.end_position();
    let snippet = call.utf8_text(source.as_bytes()).unwrap_or("").to_string();
    Some(SizeofMulFinding {
        allocator: function_name.to_string(),
        variable_operand,
        sizeof_operand,
        file_path: file_path.to_string(),
        line: start.row + 1,
        column: start.column + 1,
        end_line: end.row + 1,
        end_column: end.column + 1,
        snippet,
    })
}

/// If `node` is a binary `*` expression with one side `sizeof(...)`
/// and the other side a non-literal operand, return both as
/// `(sizeof_text, variable_text)`. Otherwise `None`.
fn extract_sizeof_mul_operands(node: Node<'_>, source: &str) -> Option<(String, String)> {
    if node.kind() != "binary_expression" {
        return None;
    }
    let operator = node
        .child_by_field_name("operator")
        .and_then(|child| child.utf8_text(source.as_bytes()).ok())?;
    if operator != "*" {
        return None;
    }
    let left = unwrap_paren(node.child_by_field_name("left")?);
    let right = unwrap_paren(node.child_by_field_name("right")?);
    match (is_sizeof(left), is_sizeof(right)) {
        (true, false) if !is_integer_literal(right) => {
            Some((text_of(left, source), text_of(right, source)))
        }
        (false, true) if !is_integer_literal(left) => {
            Some((text_of(right, source), text_of(left, source)))
        }
        _ => None,
    }
}

fn is_sizeof(node: Node<'_>) -> bool {
    node.kind() == "sizeof_expression"
}

fn is_integer_literal(node: Node<'_>) -> bool {
    node.kind() == "number_literal"
}

fn text_of(node: Node<'_>, source: &str) -> String {
    node.utf8_text(source.as_bytes()).unwrap_or("").to_string()
}

/// A potential NULL-pointer dereference: a local pointer initialised
/// by an allocator that may return NULL is dereferenced (or passed to
/// a function known to dereference its argument) without an
/// intervening NULL check that leaves the function on the NULL branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NullDerefFinding {
    /// Name of the pointer variable.
    pub pointer: String,
    /// Allocator function whose result was assigned to the pointer.
    pub allocator: String,
    /// File the finding is reported against.
    pub file_path: String,
    /// 1-indexed line/column of the offending use.
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    /// Source text of the offending use.
    pub snippet: String,
}

/// Scan C/C++ source for the CWE-476 pattern: local pointer assigned
/// from an allocator (`malloc` / `calloc` / `realloc` / `strdup` /
/// `strndup` / `aligned_alloc`) and then used before any NULL check
/// that diverts the function on the NULL branch.
///
/// Soundness: "miss rather than misreport". A use is only flagged when
/// no recognised early-leave NULL check (`if (!p) return …`,
/// `if (p == NULL) return …`, `if (NULL == p) return …`) precedes it
/// in source order, and the use is not inside an `if (p)` /
/// `if (p != NULL)` guarded block. Any intervening shape the analyser
/// does not recognise causes the alloc site to be silently dropped.
pub fn scan_null_deref_after_alloc(code: &str, file_path: &str) -> Vec<NullDerefFinding> {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(code, None) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition" {
            if let Some(body) = node.child_by_field_name("body") {
                collect_null_deref_findings(body, code, file_path, &mut findings);
            }
            continue;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    findings
}

#[derive(Debug, Clone)]
struct AllocSite {
    name: String,
    allocator: String,
    alloc_end_byte: usize,
}

fn collect_null_deref_findings(
    body: Node<'_>,
    source: &str,
    file_path: &str,
    out: &mut Vec<NullDerefFinding>,
) {
    let alloc_sites = collect_alloc_sites(body, source);
    let null_checks = collect_null_check_positions(body, source);
    let safe_blocks = collect_safe_blocks(body, source);

    for site in alloc_sites {
        if let Some(use_node) = first_unchecked_use(body, &site, source, &null_checks, &safe_blocks)
        {
            let start = use_node.start_position();
            let end = use_node.end_position();
            let snippet = use_node
                .utf8_text(source.as_bytes())
                .unwrap_or("")
                .to_string();
            out.push(NullDerefFinding {
                pointer: site.name,
                allocator: site.allocator,
                file_path: file_path.to_string(),
                line: start.row + 1,
                column: start.column + 1,
                end_line: end.row + 1,
                end_column: end.column + 1,
                snippet,
            });
        }
    }
}

fn collect_alloc_sites(body: Node<'_>, source: &str) -> Vec<AllocSite> {
    let mut sites = Vec::new();
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "declaration" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "init_declarator" {
                        if let (Some(decl), Some(value)) = (
                            child.child_by_field_name("declarator"),
                            child.child_by_field_name("value"),
                        ) {
                            if let (Some(name), Some(allocator)) = (
                                extract_pointer_decl_name(decl, source),
                                recognise_allocator_function_name(value, source),
                            ) {
                                sites.push(AllocSite {
                                    name,
                                    allocator,
                                    alloc_end_byte: child.end_byte(),
                                });
                            }
                        }
                    }
                }
            }
            "assignment_expression" => {
                if let (Some(lhs), Some(rhs)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    if lhs.kind() == "identifier" {
                        if let Ok(name) = lhs.utf8_text(source.as_bytes()) {
                            if let Some(allocator) = recognise_allocator_function_name(rhs, source)
                            {
                                sites.push(AllocSite {
                                    name: name.to_string(),
                                    allocator,
                                    alloc_end_byte: node.end_byte(),
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    sites
}

fn extract_pointer_decl_name(decl: Node<'_>, source: &str) -> Option<String> {
    match decl.kind() {
        "pointer_declarator" | "parenthesized_declarator" => {
            let inner = decl.child_by_field_name("declarator")?;
            extract_pointer_decl_name(inner, source)
        }
        "identifier" => decl.utf8_text(source.as_bytes()).ok().map(str::to_string),
        _ => None,
    }
}

fn recognise_allocator_function_name(node: Node<'_>, source: &str) -> Option<String> {
    let call = unwrap_to_call(node)?;
    let function = call.child_by_field_name("function")?;
    let name = function.utf8_text(source.as_bytes()).ok()?;
    match name {
        "malloc" | "calloc" | "realloc" | "strdup" | "strndup" | "aligned_alloc" => {
            Some(name.to_string())
        }
        _ => None,
    }
}

/// Map of pointer name -> sorted byte positions of `if`-statements that
/// recognise the pointer as NULL and divert the function on that branch
/// (return / goto / break with the NULL branch active).
type NullCheckMap = std::collections::HashMap<String, Vec<usize>>;

/// Map of pointer name -> list of (start_byte, end_byte) ranges of
/// `if (p)` / `if (p != NULL)` blocks. Uses of `p` inside one of these
/// ranges are guarded.
type SafeBlockMap = std::collections::HashMap<String, Vec<(usize, usize)>>;

fn collect_null_check_positions(body: Node<'_>, source: &str) -> NullCheckMap {
    let mut out: NullCheckMap = std::collections::HashMap::new();
    walk_for_null_checks(body, source, &mut out);
    for positions in out.values_mut() {
        positions.sort_unstable();
    }
    out
}

fn walk_for_null_checks(node: Node<'_>, source: &str, out: &mut NullCheckMap) {
    if node.kind() == "if_statement" {
        if let Some((name, kind)) = classify_null_check(node, source) {
            if matches!(kind, NullCheckKind::EarlyLeaveOnNull) {
                out.entry(name).or_default().push(node.start_byte());
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_for_null_checks(child, source, out);
    }
}

fn collect_safe_blocks(body: Node<'_>, source: &str) -> SafeBlockMap {
    let mut out: SafeBlockMap = std::collections::HashMap::new();
    walk_for_safe_blocks(body, source, &mut out);
    out
}

fn walk_for_safe_blocks(node: Node<'_>, source: &str, out: &mut SafeBlockMap) {
    if node.kind() == "if_statement" {
        if let Some((name, kind)) = classify_null_check(node, source) {
            if matches!(kind, NullCheckKind::TruthyGuardedBlock) {
                if let Some(consequence) = node.child_by_field_name("consequence") {
                    out.entry(name)
                        .or_default()
                        .push((consequence.start_byte(), consequence.end_byte()));
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_for_safe_blocks(child, source, out);
    }
}

#[derive(Debug, Clone, Copy)]
enum NullCheckKind {
    /// `if (!p) return …` / `if (p == NULL) return …` — divert on NULL.
    EarlyLeaveOnNull,
    /// `if (p)` / `if (p != NULL)` — uses inside the consequence body
    /// are guarded.
    TruthyGuardedBlock,
}

fn classify_null_check(if_stmt: Node<'_>, source: &str) -> Option<(String, NullCheckKind)> {
    let condition = if_stmt.child_by_field_name("condition")?;
    // condition is typically `parenthesized_expression` wrapping the actual test
    let inner = strip_parens(condition);
    let consequence = if_stmt.child_by_field_name("consequence");
    if let Some((name, polarity)) = match_null_condition(inner, source) {
        return Some(match polarity {
            NullPolarity::TrueIfNull => {
                if consequence
                    .map(|c| branch_leaves_function(c))
                    .unwrap_or(false)
                {
                    (name, NullCheckKind::EarlyLeaveOnNull)
                } else {
                    return None;
                }
            }
            NullPolarity::TrueIfNonNull => (name, NullCheckKind::TruthyGuardedBlock),
        });
    }
    None
}

fn strip_parens(node: Node<'_>) -> Node<'_> {
    match node.kind() {
        "parenthesized_expression" => (0..(node.named_child_count() as u32))
            .filter_map(|idx| node.named_child(idx))
            .next()
            .map(strip_parens)
            .unwrap_or(node),
        _ => node,
    }
}

#[derive(Debug, Clone, Copy)]
enum NullPolarity {
    /// Condition is true when the pointer is NULL: `!p`, `p == NULL`,
    /// `p == 0`, `NULL == p`, `0 == p`.
    TrueIfNull,
    /// Condition is true when the pointer is non-NULL: `p`,
    /// `p != NULL`, `p != 0`, `NULL != p`, `0 != p`.
    TrueIfNonNull,
}

fn match_null_condition(node: Node<'_>, source: &str) -> Option<(String, NullPolarity)> {
    match node.kind() {
        "unary_expression" => {
            let op = node.child_by_field_name("operator")?;
            let op_text = op.utf8_text(source.as_bytes()).ok()?;
            if op_text == "!" {
                let arg = node.child_by_field_name("argument")?;
                if arg.kind() == "identifier" {
                    let name = arg.utf8_text(source.as_bytes()).ok()?;
                    return Some((name.to_string(), NullPolarity::TrueIfNull));
                }
            }
            None
        }
        "binary_expression" => {
            let op = node.child_by_field_name("operator")?;
            let op_text = op.utf8_text(source.as_bytes()).ok()?;
            let left = node.child_by_field_name("left")?;
            let right = node.child_by_field_name("right")?;
            let (name, _other) = pick_identifier_and_null(left, right, source)?;
            match op_text {
                "==" => Some((name, NullPolarity::TrueIfNull)),
                "!=" => Some((name, NullPolarity::TrueIfNonNull)),
                _ => None,
            }
        }
        "identifier" => {
            // bare `if (p)` — truthy means non-NULL
            let name = node.utf8_text(source.as_bytes()).ok()?;
            Some((name.to_string(), NullPolarity::TrueIfNonNull))
        }
        _ => None,
    }
}

fn pick_identifier_and_null<'a>(
    a: Node<'a>,
    b: Node<'a>,
    source: &str,
) -> Option<(String, Node<'a>)> {
    if is_null_literal(a, source) && b.kind() == "identifier" {
        Some((b.utf8_text(source.as_bytes()).ok()?.to_string(), a))
    } else if is_null_literal(b, source) && a.kind() == "identifier" {
        Some((a.utf8_text(source.as_bytes()).ok()?.to_string(), b))
    } else {
        None
    }
}

fn is_null_literal(node: Node<'_>, source: &str) -> bool {
    let text = node.utf8_text(source.as_bytes()).unwrap_or("").trim();
    matches!(text, "NULL" | "nullptr" | "0" | "((void *)0)" | "(void *)0")
}

fn branch_leaves_function(node: Node<'_>) -> bool {
    match node.kind() {
        "return_statement" | "goto_statement" => true,
        "compound_statement" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if branch_leaves_function(child) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

fn first_unchecked_use<'a>(
    body: Node<'a>,
    site: &AllocSite,
    source: &str,
    null_checks: &NullCheckMap,
    safe_blocks: &SafeBlockMap,
) -> Option<Node<'a>> {
    let checks_for_name = null_checks.get(&site.name);
    let safe_for_name = safe_blocks.get(&site.name);
    let mut stack = vec![body];
    let mut candidates: Vec<Node<'a>> = Vec::new();
    while let Some(node) = stack.pop() {
        if node.end_byte() <= site.alloc_end_byte {
            continue;
        }
        if is_pointer_use_of(node, &site.name, source) {
            candidates.push(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    candidates.sort_by_key(|node| node.start_byte());
    for use_node in candidates {
        let use_start = use_node.start_byte();
        if use_start <= site.alloc_end_byte {
            continue;
        }
        // Guarded inside `if (p)` block?
        if let Some(blocks) = safe_for_name {
            if blocks
                .iter()
                .any(|(start, end)| use_start >= *start && use_node.end_byte() <= *end)
            {
                continue;
            }
        }
        // Preceded by an early-leave NULL check?
        if let Some(check_positions) = checks_for_name {
            if check_positions
                .iter()
                .any(|pos| *pos > site.alloc_end_byte && *pos < use_start)
            {
                continue;
            }
        }
        return Some(use_node);
    }
    None
}

/// Functions in the C standard library known to dereference their
/// first pointer argument. The list is deliberately conservative —
/// `printf`, `fprintf`, `free` and similar are excluded because
/// `free(NULL)` is defined and `printf` with `%s NULL` does not always
/// deref. Keep the set small to satisfy the "miss rather than misreport"
/// rule.
const POINTER_DEREF_FUNCTIONS: &[&str] = &[
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "strlen",
    "strnlen",
    "strcmp",
    "strncmp",
    "strcasecmp",
    "strncasecmp",
    "strchr",
    "strrchr",
    "strstr",
    "memcpy",
    "memmove",
    "memset",
    "mempcpy",
    "memcmp",
    "memchr",
    "sprintf",
    "snprintf",
    "vsprintf",
    "vsnprintf",
];

fn is_pointer_use_of(node: Node<'_>, name: &str, source: &str) -> bool {
    match node.kind() {
        "pointer_expression" | "unary_expression" => {
            // `*p`. tree-sitter-c parses dereferences as
            // `pointer_expression` and the logical-not / arithmetic
            // negation forms as `unary_expression`. Both expose
            // `operator` and `argument` fields, so we accept either
            // node kind here and gate on the actual operator text.
            let Some(op) = node.child_by_field_name("operator") else {
                return false;
            };
            if op.utf8_text(source.as_bytes()).ok() != Some("*") {
                return false;
            }
            let Some(arg) = node.child_by_field_name("argument") else {
                return false;
            };
            arg.kind() == "identifier" && arg.utf8_text(source.as_bytes()).ok() == Some(name)
        }
        "subscript_expression" => {
            // `p[i]`
            let Some(arg) = node.child_by_field_name("argument") else {
                return false;
            };
            arg.kind() == "identifier" && arg.utf8_text(source.as_bytes()).ok() == Some(name)
        }
        "field_expression" => {
            // `p->x` — operator is `->`
            let Some(arg) = node.child_by_field_name("argument") else {
                return false;
            };
            let Some(op) = node.child_by_field_name("operator") else {
                return false;
            };
            if op.utf8_text(source.as_bytes()).ok() != Some("->") {
                return false;
            }
            arg.kind() == "identifier" && arg.utf8_text(source.as_bytes()).ok() == Some(name)
        }
        "call_expression" => {
            let Some(function) = node.child_by_field_name("function") else {
                return false;
            };
            let Some(fname) = function.utf8_text(source.as_bytes()).ok() else {
                return false;
            };
            if !POINTER_DEREF_FUNCTIONS.contains(&fname) {
                return false;
            }
            let Some(arguments) = node.child_by_field_name("arguments") else {
                return false;
            };
            let Some(first) = arguments.named_child(0) else {
                return false;
            };
            first.kind() == "identifier" && first.utf8_text(source.as_bytes()).ok() == Some(name)
        }
        _ => false,
    }
}

/// A request to find a function definition outside of the current
/// translation unit. The heap-overflow analyser consults the context
/// when its per-TU summary cache misses a callee — without it, an
/// allocation in `lib/helper.c` paired with a write in `util/caller.c`
/// is invisible to the per-file pass.
///
/// Implementations live outside this module: the MCP layer wraps the
/// project call graph; tests use a hand-rolled mock. Implementations
/// must never guess on ambiguous resolution — return `None` instead, so
/// the analyser short-circuits to `Unknown` rather than emitting a
/// false positive against the wrong definition.
pub trait CrossFileContext {
    /// Locate the function named `name` somewhere in the project.
    /// `caller_file` is the file containing the call site —
    /// implementations use it to resolve `static` symbol collisions in
    /// favour of the definition in the caller's own translation unit.
    fn locate_function(&self, name: &str, caller_file: &str) -> Option<FunctionLocation>;
}

/// A function definition surfaced by [`CrossFileContext::locate_function`].
#[derive(Debug, Clone)]
pub struct FunctionLocation {
    /// Path to the file containing the definition.
    pub file_path: String,
    /// Full source of that file, ready for tree-sitter to parse.
    pub source: String,
}

/// A no-op resolver. Every lookup returns `None`, restoring the
/// per-translation-unit-only behaviour the analyser had before
/// cross-TU resolution existed. Used by single-file entry points
/// (tests and the per-file `scan_security` pass) where no project
/// context is available.
pub struct NullContext;

impl CrossFileContext for NullContext {
    fn locate_function(&self, _name: &str, _caller_file: &str) -> Option<FunctionLocation> {
        None
    }
}

/// Parse `code` as C, walk every function definition, and return the
/// heap-overflow findings the analyser can prove. Top-level entry
/// point used by the security-rules engine for CWE-122.
///
/// This is the per-translation-unit entry point. Callers that have a
/// project context (call graph + file reader) should use
/// [`scan_heap_overflows_with_context`] instead to pick up overflows
/// that span TU boundaries.
pub fn scan_heap_overflows(code: &str, file_path: &str) -> Vec<HeapOverflowFinding> {
    scan_heap_overflows_with_context(code, file_path, &NullContext)
}

/// Like [`scan_heap_overflows`] but consults `ctx` when the
/// translation-unit-local summary cache misses a callee — closes the
/// gap that left allocations in a helper TU paired with writes in a
/// caller TU invisible to the analyser.
pub fn scan_heap_overflows_with_context(
    code: &str,
    file_path: &str,
    ctx: &dyn CrossFileContext,
) -> Vec<HeapOverflowFinding> {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(code, None) else {
        return Vec::new();
    };

    let cache = build_function_summary_cache(tree.root_node(), code);
    let resolver = CrossFileResolver::new(file_path, ctx);

    let mut findings = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition" {
            if let Some(body) = node.child_by_field_name("body") {
                let allocations =
                    collect_allocation_sizes_with_xfile(body, code, &cache, &resolver);
                let write_sites = collect_write_sites(body, code);
                findings.extend(detect_overflows(&allocations, &write_sites, file_path));
            }
            // Function definitions don't nest in C; no need to recurse.
            continue;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    findings
}

/// Per-scan state for cross-translation-unit allocator resolution.
/// Built once per `scan_heap_overflows_with_context` call and threaded
/// down to [`recognise_allocator_call_with_cache`]. The memo prevents
/// re-parsing the same external file for repeat lookups and breaks
/// recursion by treating an in-progress entry as `Unresolvable`.
struct CrossFileResolver<'a> {
    current_file: &'a str,
    ctx: &'a dyn CrossFileContext,
    memo: RefCell<HashMap<String, MaybeSummary>>,
}

#[derive(Clone)]
enum MaybeSummary {
    InProgress,
    Resolved(FunctionAllocationSummary),
    Unresolvable,
}

impl<'a> CrossFileResolver<'a> {
    fn new(current_file: &'a str, ctx: &'a dyn CrossFileContext) -> Self {
        Self {
            current_file,
            ctx,
            memo: RefCell::new(HashMap::new()),
        }
    }

    /// Resolve a callee name to its function-allocation summary by
    /// asking the context and then summarising the returned source.
    /// Returns `None` when the context cannot disambiguate the name,
    /// when the resolved file fails to parse, or when the callee has
    /// no recognisable allocation shape (i.e. its summary would be
    /// `Unknown` anyway).
    fn resolve(&self, function_name: &str) -> Option<FunctionAllocationSummary> {
        let location = self.ctx.locate_function(function_name, self.current_file)?;
        let cache_key = format!("{}::{}", location.file_path, function_name);

        if let Some(existing) = self.memo.borrow().get(&cache_key).cloned() {
            return match existing {
                MaybeSummary::Resolved(summary) => Some(summary),
                MaybeSummary::InProgress | MaybeSummary::Unresolvable => None,
            };
        }
        self.memo
            .borrow_mut()
            .insert(cache_key.clone(), MaybeSummary::InProgress);

        let summary = parse_and_summarise_function(&location.source, function_name);
        let outcome = match &summary {
            Some(s) => MaybeSummary::Resolved(s.clone()),
            None => MaybeSummary::Unresolvable,
        };
        self.memo.borrow_mut().insert(cache_key, outcome);
        summary
    }
}

/// Parse `source` as C and return the allocation summary of the
/// function named `function_name`, or `None` when the file does not
/// parse or the function is absent / has no recognisable allocation.
fn parse_and_summarise_function(
    source: &str,
    function_name: &str,
) -> Option<FunctionAllocationSummary> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&tree_sitter_c::LANGUAGE.into()).ok()?;
    let tree = parser.parse(source, None)?;
    let cache = build_function_summary_cache(tree.root_node(), source);
    let summary = cache.get(function_name)?.clone();
    if matches!(summary.return_size, SizeExpr::Unknown) {
        return None;
    }
    Some(summary)
}

/// Cross-file-aware variant of [`collect_allocation_sizes_with_cache`].
/// Used only by [`scan_heap_overflows_with_context`]; the public
/// cache-aware entry stays per-TU so direct callers (tests, single-file
/// scans) get the predictable per-TU semantics they always had.
fn collect_allocation_sizes_with_xfile(
    function_body: Node<'_>,
    source: &str,
    cache: &HashMap<String, FunctionAllocationSummary>,
    resolver: &CrossFileResolver<'_>,
) -> HashMap<String, SizeExpr> {
    let mut out = HashMap::new();
    collect_into(function_body, source, cache, &mut out, Some(resolver));
    out
}

/// Split a [`SizeExpr`] into its multiset of `StrlenOf` arguments and
/// the sum of its constant terms. `Unknown` collapses to `(vec![], 0)`
/// — callers must short-circuit on `Unknown` before calling this.
fn decompose_size(expr: &SizeExpr) -> (Vec<String>, u64) {
    match expr {
        SizeExpr::Constant(value) => (Vec::new(), *value),
        SizeExpr::StrlenOf(name) => (vec![name.clone()], 0),
        SizeExpr::Sum(parts) => {
            let mut strlens = Vec::new();
            let mut constant: u64 = 0;
            for part in parts {
                match part {
                    SizeExpr::Constant(value) => {
                        constant = constant.saturating_add(*value);
                    }
                    SizeExpr::StrlenOf(name) => strlens.push(name.clone()),
                    SizeExpr::Sum(_) | SizeExpr::Unknown => {
                        // SizeExpr canonicalisation rules out nested
                        // Sums and Unknown in Sum bodies.
                    }
                }
            }
            (strlens, constant)
        }
        SizeExpr::Unknown => (Vec::new(), 0),
    }
}

/// Return `true` iff `big` contains every element of `small` with at
/// least the same multiplicity. Used to confirm that a write's
/// symbolic terms cover the allocation's terms before a constant-only
/// inequality is enough to prove overflow.
fn multiset_contains_all(big: &[String], small: &[String]) -> bool {
    let mut remaining: Vec<&str> = big.iter().map(String::as_str).collect();
    for needed in small {
        if let Some(idx) = remaining.iter().position(|item| item == needed) {
            remaining.swap_remove(idx);
        } else {
            return false;
        }
    }
    true
}

/// Source text of `node` if it is a plain identifier or field
/// reference, else `None`. Used to key allocation lookups by the same
/// string the allocation map uses.
fn extract_simple_destination(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_expression" => {
            node.utf8_text(source.as_bytes()).ok().map(str::to_string)
        }
        _ => None,
    }
}

/// Bound on the length (in bytes, not counting NUL) of a string
/// argument to a `str*` call. Identifiers and field references emit
/// `StrlenOf(text)`; string literals collapse to the literal's
/// byte length. Anything else is `Unknown`.
fn string_source_size(node: Node<'_>, source: &str) -> SizeExpr {
    match node.kind() {
        "identifier" | "field_expression" => node
            .utf8_text(source.as_bytes())
            .ok()
            .map(|text| SizeExpr::StrlenOf(text.to_string()))
            .unwrap_or(SizeExpr::Unknown),
        "string_literal" => extract_string_literal_content(node, source)
            .map(|content| SizeExpr::Constant(content.len() as u64))
            .unwrap_or(SizeExpr::Unknown),
        _ => SizeExpr::Unknown,
    }
}

/// Walk a C function body and return a map from each allocation
/// target's source text to the [`SizeExpr`] the corresponding
/// allocator was called with.
///
/// Recognised allocators:
///
/// * `malloc(size)` — maps to `parse_size_expression(size)`
/// * `calloc(nmemb, size)` — folds to a constant only when both
///   arguments parse to `Constant`; otherwise `Unknown`
/// * `realloc(pointer, size)` — maps to `parse_size_expression(size)`
///
/// Recognised left-hand sides:
///
/// * plain `identifier`: `p = malloc(...)`
/// * `field_expression`: `dst->buf = malloc(...)`, keyed by the full
///   `dst->buf` source text
/// * `pointer_declarator` wrapping any of the above, for the
///   declaration form `char *p = malloc(...)`
///
/// A `(T *)` cast around the allocator call is unwrapped. Any other
/// shape is silently skipped; this function never raises and never
/// returns false positives — unrecognised allocations simply do not
/// appear in the map.
pub fn collect_allocation_sizes(
    function_body: Node<'_>,
    source: &str,
) -> HashMap<String, SizeExpr> {
    collect_allocation_sizes_with_cache(function_body, source, &HashMap::new())
}

/// Cache-aware variant of [`collect_allocation_sizes`]. Resolves
/// `char *buf = helper();` shapes when `helper` appears in the
/// translation-unit cache built by
/// [`build_function_summary_cache`]. The cache lets the analyser see
/// the allocation through one call hop without losing precision.
pub fn collect_allocation_sizes_with_cache(
    function_body: Node<'_>,
    source: &str,
    cache: &HashMap<String, FunctionAllocationSummary>,
) -> HashMap<String, SizeExpr> {
    let mut out = HashMap::new();
    collect_into(function_body, source, cache, &mut out, None);
    out
}

/// Summarise a single function: return its source-level name together
/// with the allocation map produced for its body.
///
/// Accepts a `function_definition` node. Returns `None` if `node` is
/// not a function definition, if the function has no extractable
/// identifier (e.g. an unnamed declarator shape we do not recognise),
/// or if the body is missing.
pub fn summarise_function<'a>(
    function_definition: Node<'a>,
    source: &str,
) -> Option<(String, HashMap<String, SizeExpr>)> {
    if function_definition.kind() != "function_definition" {
        return None;
    }
    let name = extract_function_name(function_definition, source)?;
    let body = function_definition.child_by_field_name("body")?;
    Some((name, collect_allocation_sizes(body, source)))
}

/// Walk a translation-unit root node and return one allocation map per
/// function definition keyed by function name. Used by the
/// cross-function cache: callers that see `char *buf = helper();`
/// need to know what `helper` allocated to size `buf`.
///
/// Skips nameless or duplicate definitions silently — duplicates
/// resolve to the last one encountered, mirroring how the linker would
/// see the translation unit.
pub fn summarise_translation_unit(
    root: Node<'_>,
    source: &str,
) -> HashMap<String, HashMap<String, SizeExpr>> {
    let mut out = HashMap::new();
    summarise_into(root, source, &mut out);
    out
}

fn summarise_into(
    node: Node<'_>,
    source: &str,
    out: &mut HashMap<String, HashMap<String, SizeExpr>>,
) {
    if node.kind() == "function_definition" {
        if let Some((name, allocations)) = summarise_function(node, source) {
            out.insert(name, allocations);
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        summarise_into(child, source, out);
    }
}

/// Extract the source-level identifier of a `function_definition` node
/// by descending the declarator chain. Handles the common shapes:
/// plain `name(...)`, `*name(...)`, and any number of nested pointer
/// declarators.
fn extract_function_name(function_definition: Node<'_>, source: &str) -> Option<String> {
    let mut declarator = function_definition.child_by_field_name("declarator")?;
    loop {
        match declarator.kind() {
            "function_declarator" => {
                let inner = declarator.child_by_field_name("declarator")?;
                return inner.utf8_text(source.as_bytes()).ok().map(str::to_string);
            }
            "pointer_declarator" | "parenthesized_declarator" => {
                declarator = declarator.child_by_field_name("declarator")?;
            }
            _ => return None,
        }
    }
}

fn collect_into(
    node: Node<'_>,
    source: &str,
    cache: &HashMap<String, FunctionAllocationSummary>,
    out: &mut HashMap<String, SizeExpr>,
    resolver: Option<&CrossFileResolver<'_>>,
) {
    match node.kind() {
        "call_expression" => {
            if let Some((destination, size)) = recognise_asprintf_call(node, source) {
                out.insert(destination, size);
            }
        }
        "declaration" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "init_declarator" {
                    let declarator = child.child_by_field_name("declarator");
                    let value = child.child_by_field_name("value");
                    if let (Some(decl), Some(rhs)) = (declarator, value) {
                        if let Some(name) = extract_lhs_name(decl, source) {
                            if let Some(size) =
                                recognise_allocator_call_with_cache(rhs, source, cache, resolver)
                            {
                                out.insert(name, size);
                            }
                        }
                    }
                }
            }
        }
        "assignment_expression" => {
            let lhs = node.child_by_field_name("left");
            let rhs = node.child_by_field_name("right");
            if let (Some(lhs), Some(rhs)) = (lhs, rhs) {
                if let Some(name) = extract_lhs_name(lhs, source) {
                    if let Some(size) =
                        recognise_allocator_call_with_cache(rhs, source, cache, resolver)
                    {
                        out.insert(name, size);
                    }
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_into(child, source, cache, out, resolver);
    }
}

fn extract_lhs_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_expression" => {
            node.utf8_text(source.as_bytes()).ok().map(str::to_string)
        }
        "pointer_declarator" => {
            for idx in 0..(node.named_child_count() as u32) {
                if let Some(child) = node.named_child(idx) {
                    if let Some(name) = extract_lhs_name(child, source) {
                        return Some(name);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Recognise an `asprintf(&dest, fmt, args...)` or
/// `vasprintf(&dest, fmt, va_list)` call and return the destination's
/// source text together with the [`SizeExpr`] the call allocates.
///
/// `asprintf` writes the formatted output plus a NUL terminator into
/// a freshly malloc'd buffer. So the allocation is exactly
/// `write_size_of_format(fmt, args) + 1` bytes — assuming the format
/// is fully modelled. `vasprintf` takes a `va_list` whose contents
/// the analyser cannot inspect, so it always returns `Unknown` while
/// still recording the destination so downstream code knows the
/// buffer exists.
///
/// Returns `None` if the call is not asprintf/vasprintf, if the first
/// argument is not an address-of expression, or if (for asprintf) the
/// format string is not a plain literal that can be decoded.
fn recognise_asprintf_call(call: Node<'_>, source: &str) -> Option<(String, SizeExpr)> {
    let function_name = call
        .child_by_field_name("function")?
        .utf8_text(source.as_bytes())
        .ok()?;
    if function_name != "asprintf" && function_name != "vasprintf" {
        return None;
    }

    let arguments = call.child_by_field_name("arguments")?;
    let argument_nodes: Vec<Node<'_>> = (0..(arguments.named_child_count() as u32))
        .filter_map(|idx| arguments.named_child(idx))
        .collect();
    if argument_nodes.len() < 2 {
        return None;
    }

    let destination = extract_address_of_target(argument_nodes[0], source)?;

    if function_name == "vasprintf" {
        // The format args come from a va_list — opaque to us — and
        // even a literal format can't be combined with unknown args.
        // Skip format extraction so we still record the destination.
        return Some((destination, SizeExpr::Unknown));
    }

    let format = extract_string_literal_content(argument_nodes[1], source)?;

    let argument_names: Vec<String> = argument_nodes[2..]
        .iter()
        .map(|node| node.utf8_text(source.as_bytes()).unwrap_or("").to_string())
        .collect();

    let written = write_size_of_format(&format, &argument_names);
    Some((destination, written.plus_constant(1)))
}

/// If `node` represents `&expr`, return the source text of `expr`.
/// Otherwise return `None`. Falls back to a leading-`&` text strip so
/// it works across tree-sitter-c versions that disagree on the
/// `pointer_expression` vs `unary_expression` node kind for `&`.
fn extract_address_of_target(node: Node<'_>, source: &str) -> Option<String> {
    let text = node.utf8_text(source.as_bytes()).ok()?.trim();
    let stripped = text.strip_prefix('&')?.trim();
    if stripped.is_empty() {
        return None;
    }
    Some(stripped.to_string())
}

/// Decode the contents of a `string_literal` node into the byte
/// sequence the C compiler would see. Returns `None` if the literal
/// contains an escape sequence we do not know how to decode — that
/// preserves the analyser's "miss rather than misreport" stance.
fn extract_string_literal_content(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "string_literal" {
        return None;
    }
    let mut decoded = String::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "string_content" => {
                decoded.push_str(child.utf8_text(source.as_bytes()).ok()?);
            }
            "escape_sequence" => {
                let raw = child.utf8_text(source.as_bytes()).ok()?;
                let replacement = match raw {
                    "\\n" => "\n",
                    "\\t" => "\t",
                    "\\r" => "\r",
                    "\\0" => "\0",
                    "\\\\" => "\\",
                    "\\\"" => "\"",
                    _ => return None,
                };
                decoded.push_str(replacement);
            }
            "\"" => {}
            _ => return None,
        }
    }
    Some(decoded)
}

/// Summary of a function's allocation behaviour usable as a one-hop
/// substitute for an allocator call. The size is expressed in terms of
/// the function's *parameter names*; [`substitute_parameters`] swaps
/// those for the call-site argument expressions to produce a size
/// scoped to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionAllocationSummary {
    /// Parameter names in declaration order. May be empty for varargs
    /// or unnamed parameters; in either case [`substitute_parameters`]
    /// leaves the corresponding terms untouched.
    pub parameter_names: Vec<String>,
    /// Size returned by the function, in terms of the parameter names.
    /// `Unknown` when the analyser cannot identify a single
    /// well-defined return size across every reachable `return`.
    pub return_size: SizeExpr,
}

/// Build a translation-unit-wide cache of return-allocation summaries
/// for every function definition rooted under `root`. Callers that see
/// `char *buf = helper(arg);` use this cache to resolve `buf`'s size
/// instead of recording an Unknown.
///
/// A function is summarised only when every reachable `return` returns
/// a recognised allocator call with the same symbolic size — otherwise
/// the entry is omitted, mirroring the analyser's "miss rather than
/// misreport" stance.
pub fn build_function_summary_cache(
    root: Node<'_>,
    source: &str,
) -> HashMap<String, FunctionAllocationSummary> {
    let mut out = HashMap::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition" {
            if let Some((name, summary)) = summarise_function_allocation(node, source) {
                out.insert(name, summary);
            }
            continue;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

/// Summarise a function for the cross-function cache. Returns the
/// function's name and the [`FunctionAllocationSummary`] derived from
/// its parameter list and return statements. Returns `None` when the
/// function has no extractable name or no body.
pub fn summarise_function_allocation(
    function_definition: Node<'_>,
    source: &str,
) -> Option<(String, FunctionAllocationSummary)> {
    if function_definition.kind() != "function_definition" {
        return None;
    }
    let name = extract_function_name(function_definition, source)?;
    let parameter_names = extract_parameter_names(function_definition, source);
    let body = function_definition.child_by_field_name("body")?;
    let return_size = compute_return_size(body, source);
    Some((
        name,
        FunctionAllocationSummary {
            parameter_names,
            return_size,
        },
    ))
}

/// Substitute call-site argument expressions for the function's
/// parameter names inside a return-size expression. `StrlenOf(p)` for
/// a parameter `p` becomes `StrlenOf(argument_text)`; everything else
/// is preserved verbatim.
pub fn substitute_parameters(
    expr: &SizeExpr,
    parameter_names: &[String],
    argument_texts: &[String],
) -> SizeExpr {
    match expr {
        SizeExpr::Constant(value) => SizeExpr::Constant(*value),
        SizeExpr::StrlenOf(name) => parameter_names
            .iter()
            .position(|param| param == name)
            .and_then(|idx| argument_texts.get(idx).cloned())
            .map(SizeExpr::StrlenOf)
            .unwrap_or_else(|| SizeExpr::StrlenOf(name.clone())),
        SizeExpr::Sum(parts) => {
            let mut result = SizeExpr::Constant(0);
            for part in parts {
                result = result.add(substitute_parameters(part, parameter_names, argument_texts));
            }
            result
        }
        SizeExpr::Unknown => SizeExpr::Unknown,
    }
}

/// Cache-aware variant of [`recognise_allocator_call`]. Falls through
/// to the direct allocator recognition first; if that fails, tries the
/// per-TU `cache`; if that also misses and a `resolver` is supplied,
/// asks the resolver for a cross-translation-unit definition.
fn recognise_allocator_call_with_cache(
    node: Node<'_>,
    source: &str,
    cache: &HashMap<String, FunctionAllocationSummary>,
    resolver: Option<&CrossFileResolver<'_>>,
) -> Option<SizeExpr> {
    if let Some(direct) = recognise_allocator_call(node, source) {
        return Some(direct);
    }
    if cache.is_empty() && resolver.is_none() {
        return None;
    }
    let call = unwrap_to_call(node)?;
    let function_name = call
        .child_by_field_name("function")?
        .utf8_text(source.as_bytes())
        .ok()?;
    let summary = match cache.get(function_name) {
        Some(local) => local.clone(),
        None => resolver?.resolve(function_name)?,
    };
    let arguments = call.child_by_field_name("arguments")?;
    let argument_texts: Vec<String> = (0..(arguments.named_child_count() as u32))
        .filter_map(|idx| arguments.named_child(idx))
        .map(|node| node.utf8_text(source.as_bytes()).unwrap_or("").to_string())
        .collect();
    Some(substitute_parameters(
        &summary.return_size,
        &summary.parameter_names,
        &argument_texts,
    ))
}

/// Extract parameter identifier names from a `function_definition` in
/// declaration order. Parameters whose declarator cannot be resolved
/// to a plain identifier are emitted as empty strings — that keeps
/// positional indices aligned for [`substitute_parameters`], so an
/// untyped or pointer-typed parameter does not silently shift later
/// arguments' substitution mapping.
fn extract_parameter_names(function_definition: Node<'_>, source: &str) -> Vec<String> {
    let Some(parameters) = find_parameter_list(function_definition) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.children(&mut cursor) {
        if child.kind() != "parameter_declaration" {
            continue;
        }
        let declarator = child.child_by_field_name("declarator");
        let name = declarator
            .and_then(|node| extract_innermost_identifier(node, source))
            .unwrap_or_default();
        names.push(name);
    }
    names
}

fn find_parameter_list<'a>(function_definition: Node<'a>) -> Option<Node<'a>> {
    let mut declarator = function_definition.child_by_field_name("declarator")?;
    loop {
        match declarator.kind() {
            "function_declarator" => {
                return declarator.child_by_field_name("parameters");
            }
            "pointer_declarator" | "parenthesized_declarator" => {
                declarator = declarator.child_by_field_name("declarator")?;
            }
            _ => return None,
        }
    }
}

fn extract_innermost_identifier(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" => node.utf8_text(source.as_bytes()).ok().map(str::to_string),
        "pointer_declarator"
        | "parenthesized_declarator"
        | "array_declarator"
        | "function_declarator" => {
            let inner = node.child_by_field_name("declarator")?;
            extract_innermost_identifier(inner, source)
        }
        _ => None,
    }
}

/// Walk a function body and compute the single symbolic return-size
/// every reachable `return <allocator>` agrees on, or `Unknown` if any
/// return path disagrees, returns a non-allocator expression, or no
/// return exists. `return NULL` / `return 0` are treated as error
/// paths and excluded from the disagreement check — they are not
/// allocations and would otherwise force the common
/// `if (err) return 0;` plus `return out;` shape to collapse to
/// Unknown.
fn compute_return_size(body: Node<'_>, source: &str) -> SizeExpr {
    let return_expressions = collect_return_expressions(body);
    if return_expressions.is_empty() {
        return SizeExpr::Unknown;
    }
    let mut resolved_sizes: Vec<SizeExpr> = Vec::new();
    for expr in return_expressions {
        if is_null_return(expr, source) {
            continue;
        }
        if let Some(size) = recognise_allocator_call(expr, source) {
            resolved_sizes.push(size);
            continue;
        }
        if expr.kind() == "identifier" {
            let name = expr.utf8_text(source.as_bytes()).unwrap_or("").to_string();
            let cutoff = expr
                .parent()
                .map(|stmt| stmt.start_byte())
                .unwrap_or(usize::MAX);
            let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
            let size = resolve_identifier_size(body, &name, cutoff, source, &mut visited);
            resolved_sizes.push(size);
            continue;
        }
        resolved_sizes.push(SizeExpr::Unknown);
    }
    let mut iter = resolved_sizes.into_iter();
    let first_size = match iter.next() {
        Some(size) => size,
        None => return SizeExpr::Unknown,
    };
    if matches!(first_size, SizeExpr::Unknown) {
        return SizeExpr::Unknown;
    }
    for size in iter {
        if size != first_size {
            return SizeExpr::Unknown;
        }
    }
    first_size
}

/// True for return expressions that represent an error path — `0`,
/// `NULL`, or `nullptr`. These do not allocate and must not enter the
/// disagreement check.
fn is_null_return(node: Node<'_>, source: &str) -> bool {
    let text = node.utf8_text(source.as_bytes()).unwrap_or("").trim();
    text == "0" || text == "NULL" || text == "nullptr"
}

/// A populating site found by [`walk_populating_sites`]: where in the
/// body it ends, and either a resolved allocation size or the name of
/// another identifier whose size we still need to chase down.
enum PopulatingKind {
    Resolved(SizeExpr),
    PointerCopy(String),
}

struct PopulatingSite {
    end_byte: usize,
    kind: PopulatingKind,
}

/// Resolve the symbolic size of an identifier `name` by collecting every
/// statement that populates it before `cutoff_byte` and folding them
/// the same way [`compute_return_size`] folds returns: all sites must
/// agree, otherwise Unknown. Pointer-copy chains (`name = other`) are
/// followed recursively, with `visited` guarding against cycles.
fn resolve_identifier_size(
    body: Node<'_>,
    name: &str,
    cutoff_byte: usize,
    source: &str,
    visited: &mut std::collections::HashSet<String>,
) -> SizeExpr {
    if !visited.insert(name.to_string()) {
        return SizeExpr::Unknown;
    }
    let mut sites: Vec<PopulatingSite> = Vec::new();
    walk_populating_sites(body, name, source, &mut sites);
    sites.retain(|site| site.end_byte <= cutoff_byte);
    if sites.is_empty() {
        return SizeExpr::Unknown;
    }
    let mut folded: Option<SizeExpr> = None;
    for site in sites {
        let size = match site.kind {
            PopulatingKind::Resolved(size) => size,
            PopulatingKind::PointerCopy(other) => {
                resolve_identifier_size(body, &other, site.end_byte, source, visited)
            }
        };
        if matches!(size, SizeExpr::Unknown) {
            return SizeExpr::Unknown;
        }
        match folded {
            None => folded = Some(size),
            Some(ref prev) if *prev != size => return SizeExpr::Unknown,
            Some(_) => {}
        }
    }
    folded.unwrap_or(SizeExpr::Unknown)
}

/// Walk the function body and record every statement that populates
/// `name`. Recognised shapes:
/// * `name = <allocator-call>` (assignment_expression)
/// * `T name = <allocator-call>` (init_declarator with initialiser)
/// * `asprintf(&name, …)` / `vasprintf(&name, …)` (out-parameter)
/// * `name = other_ident` (pointer copy — recorded for recursive resolve)
fn walk_populating_sites(
    node: Node<'_>,
    name: &str,
    source: &str,
    sites: &mut Vec<PopulatingSite>,
) {
    match node.kind() {
        "assignment_expression" => {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                if left.kind() == "identifier"
                    && left.utf8_text(source.as_bytes()).unwrap_or("") == name
                {
                    if let Some(size) = recognise_allocator_call(right, source) {
                        sites.push(PopulatingSite {
                            end_byte: node.end_byte(),
                            kind: PopulatingKind::Resolved(size),
                        });
                    } else if right.kind() == "identifier" {
                        let other = right.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                        if !other.is_empty() && other != name {
                            sites.push(PopulatingSite {
                                end_byte: node.end_byte(),
                                kind: PopulatingKind::PointerCopy(other),
                            });
                        } else {
                            sites.push(PopulatingSite {
                                end_byte: node.end_byte(),
                                kind: PopulatingKind::Resolved(SizeExpr::Unknown),
                            });
                        }
                    } else {
                        sites.push(PopulatingSite {
                            end_byte: node.end_byte(),
                            kind: PopulatingKind::Resolved(SizeExpr::Unknown),
                        });
                    }
                }
            }
        }
        "init_declarator" => {
            if let Some(declarator) = node.child_by_field_name("declarator") {
                if let Some(decl_name) = extract_innermost_identifier(declarator, source) {
                    if decl_name == name {
                        if let Some(value) = node.child_by_field_name("value") {
                            if let Some(size) = recognise_allocator_call(value, source) {
                                sites.push(PopulatingSite {
                                    end_byte: node.end_byte(),
                                    kind: PopulatingKind::Resolved(size),
                                });
                            } else if value.kind() == "identifier" {
                                let other =
                                    value.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                                if !other.is_empty() && other != name {
                                    sites.push(PopulatingSite {
                                        end_byte: node.end_byte(),
                                        kind: PopulatingKind::PointerCopy(other),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        "call_expression" => {
            if let Some((destination, size)) = recognise_asprintf_call(node, source) {
                if destination == name {
                    sites.push(PopulatingSite {
                        end_byte: node.end_byte(),
                        kind: PopulatingKind::Resolved(size),
                    });
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_populating_sites(child, name, source, sites);
    }
}

fn collect_return_expressions<'a>(node: Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    walk_returns(node, &mut out);
    out
}

fn walk_returns<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
    if node.kind() == "return_statement" {
        for idx in 0..(node.named_child_count() as u32) {
            if let Some(child) = node.named_child(idx) {
                out.push(child);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_returns(child, out);
    }
}

fn recognise_allocator_call(node: Node<'_>, source: &str) -> Option<SizeExpr> {
    let call = unwrap_to_call(node)?;
    let function_name = call
        .child_by_field_name("function")?
        .utf8_text(source.as_bytes())
        .ok()?;
    let arguments = call.child_by_field_name("arguments")?;
    let argument_nodes: Vec<Node<'_>> = (0..(arguments.named_child_count() as u32))
        .filter_map(|idx| arguments.named_child(idx))
        .collect();
    match function_name {
        "malloc" => argument_nodes
            .first()
            .map(|node| parse_size_expression(*node, source)),
        "calloc" => {
            if argument_nodes.len() < 2 {
                return None;
            }
            let nmemb = parse_size_expression(argument_nodes[0], source);
            let size = parse_size_expression(argument_nodes[1], source);
            Some(multiply_sizes(nmemb, size))
        }
        "realloc" => argument_nodes
            .get(1)
            .map(|node| parse_size_expression(*node, source)),
        "strdup" => {
            // strdup(s) allocates exactly strlen(s) + 1 bytes. We can
            // model the size symbolically when s is a plain identifier
            // or field reference; otherwise the strlen target has no
            // stable name and we record Unknown.
            let arg = argument_nodes.first()?;
            let text = arg.utf8_text(source.as_bytes()).ok()?;
            match arg.kind() {
                "identifier" | "field_expression" => {
                    Some(SizeExpr::StrlenOf(text.to_string()).plus_constant(1))
                }
                _ => Some(SizeExpr::Unknown),
            }
        }
        "strndup" => {
            // strndup(s, n) allocates at most n + 1 bytes. Use the
            // upper bound — over-reporting is the conservative choice
            // for overflow detection (under-reporting would yield
            // false positives).
            if argument_nodes.len() < 2 {
                return None;
            }
            match parse_size_expression(argument_nodes[1], source) {
                SizeExpr::Constant(limit) => Some(SizeExpr::Constant(limit).plus_constant(1)),
                _ => Some(SizeExpr::Unknown),
            }
        }
        _ => None,
    }
}

fn unwrap_to_call(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "call_expression" => Some(node),
        "cast_expression" => node.child_by_field_name("value").and_then(unwrap_to_call),
        "parenthesized_expression" => (0..(node.named_child_count() as u32))
            .filter_map(|idx| node.named_child(idx))
            .find_map(unwrap_to_call),
        _ => None,
    }
}

fn multiply_sizes(left: SizeExpr, right: SizeExpr) -> SizeExpr {
    match (left, right) {
        (SizeExpr::Constant(left_value), SizeExpr::Constant(right_value)) => {
            SizeExpr::Constant(left_value.saturating_mul(right_value))
        }
        _ => SizeExpr::Unknown,
    }
}

/// Parse a C expression node into a [`SizeExpr`]. Returns `Unknown`
/// for anything not recognised.
///
/// Recognised forms:
///
/// * integer literals (decimal, `0x` hex; trailing `u`/`l` suffixes stripped)
/// * `strlen(name)` and `strlen(field_expr)` — emits `StrlenOf(text)`
/// * `+` of two recognised forms — emits the symbolic sum
/// * `*` of two `Constant` forms only — non-constant multiplications
///   are `Unknown` because they could overflow or depend on values
///   the analyser cannot bound
/// * parenthesised wrappers around any of the above
pub fn parse_size_expression(node: Node<'_>, source: &str) -> SizeExpr {
    match node.kind() {
        "number_literal" => {
            let text = node.utf8_text(source.as_bytes()).unwrap_or("");
            parse_c_integer(text)
        }
        "binary_expression" => {
            let operator = node
                .child_by_field_name("operator")
                .and_then(|child| child.utf8_text(source.as_bytes()).ok())
                .unwrap_or("");
            let left = node
                .child_by_field_name("left")
                .map(|child| parse_size_expression(child, source))
                .unwrap_or(SizeExpr::Unknown);
            let right = node
                .child_by_field_name("right")
                .map(|child| parse_size_expression(child, source))
                .unwrap_or(SizeExpr::Unknown);
            match operator {
                "+" => left.add(right),
                "*" => multiply_sizes(left, right),
                _ => SizeExpr::Unknown,
            }
        }
        "parenthesized_expression" => (0..(node.named_child_count() as u32))
            .filter_map(|idx| node.named_child(idx))
            .next()
            .map(|inner| parse_size_expression(inner, source))
            .unwrap_or(SizeExpr::Unknown),
        "call_expression" => {
            let function_name = node
                .child_by_field_name("function")
                .and_then(|child| child.utf8_text(source.as_bytes()).ok())
                .unwrap_or("");
            if function_name != "strlen" {
                return SizeExpr::Unknown;
            }
            let Some(arguments) = node.child_by_field_name("arguments") else {
                return SizeExpr::Unknown;
            };
            let Some(first_arg) = arguments.named_child(0) else {
                return SizeExpr::Unknown;
            };
            match first_arg.kind() {
                "identifier" | "field_expression" => first_arg
                    .utf8_text(source.as_bytes())
                    .ok()
                    .map(|text| SizeExpr::StrlenOf(text.to_string()))
                    .unwrap_or(SizeExpr::Unknown),
                _ => SizeExpr::Unknown,
            }
        }
        _ => SizeExpr::Unknown,
    }
}

fn parse_c_integer(text: &str) -> SizeExpr {
    let cleaned = text.trim_end_matches(['u', 'U', 'l', 'L']);
    if let Some(hex_digits) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        if let Ok(value) = u64::from_str_radix(hex_digits, 16) {
            return SizeExpr::Constant(value);
        }
        return SizeExpr::Unknown;
    }
    if let Ok(value) = cleaned.parse::<u64>() {
        return SizeExpr::Constant(value);
    }
    SizeExpr::Unknown
}

/// Upper bound on the number of bytes a printf-family call will write
/// for the given format string and positional argument names.
///
/// `format` is the decoded contents of the format-string literal (no
/// surrounding quotes, escape sequences already resolved — `\n` is one
/// byte). `argument_names` is the list of identifier names that follow
/// the format string in the call, in source order. The parser steps
/// through `format` and consumes one entry from `argument_names` for
/// each `%`-directive that requires an argument.
///
/// Returns [`SizeExpr::Unknown`] if any directive is not modeled. This
/// is the conservative answer — downstream callers treat Unknown
/// write-sizes as "cannot compare", which avoids false positives at
/// the cost of missing the corresponding overflow.
///
/// Modeled directives:
///
/// * `%%` — one literal byte
/// * `%s` — `strlen(arg)`, or `Constant(N)` if precision `%.Ns` is given
/// * `%c` — one byte (consumes one argument)
///
/// Width is parsed but not modeled (printf does not truncate at width,
/// only pads, so width does not change the upper bound). Length
/// modifiers (`l`, `h`, `z`, `j`, `t`, `L`) are skipped. Any other
/// conversion character (`d`, `u`, `x`, `f`, `p`, …) yields Unknown.
pub fn write_size_of_format(format: &str, argument_names: &[String]) -> SizeExpr {
    let bytes = format.as_bytes();
    let mut total = SizeExpr::Constant(0);
    let mut literal_bytes_pending: u64 = 0;
    let mut arg_cursor: usize = 0;
    let mut idx: usize = 0;

    while idx < bytes.len() {
        if bytes[idx] != b'%' {
            literal_bytes_pending += 1;
            idx += 1;
            continue;
        }

        if literal_bytes_pending > 0 {
            total = total.add(SizeExpr::Constant(literal_bytes_pending));
            literal_bytes_pending = 0;
        }

        idx += 1;
        if idx >= bytes.len() {
            return SizeExpr::Unknown;
        }

        while idx < bytes.len() && matches!(bytes[idx], b'-' | b'+' | b' ' | b'#' | b'0') {
            idx += 1;
        }

        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }

        let mut precision: Option<u64> = None;
        if idx < bytes.len() && bytes[idx] == b'.' {
            idx += 1;
            let digits_start = idx;
            while idx < bytes.len() && bytes[idx].is_ascii_digit() {
                idx += 1;
            }
            if idx == digits_start {
                return SizeExpr::Unknown;
            }
            precision = std::str::from_utf8(&bytes[digits_start..idx])
                .ok()
                .and_then(|raw| raw.parse::<u64>().ok());
            if precision.is_none() {
                return SizeExpr::Unknown;
            }
        }

        while idx < bytes.len() && matches!(bytes[idx], b'l' | b'h' | b'z' | b'j' | b't' | b'L') {
            idx += 1;
        }

        if idx >= bytes.len() {
            return SizeExpr::Unknown;
        }

        let conversion = bytes[idx];
        idx += 1;
        match conversion {
            b'%' => {
                literal_bytes_pending += 1;
            }
            b's' => {
                let piece = match precision {
                    Some(max_bytes) => SizeExpr::Constant(max_bytes),
                    None => {
                        if arg_cursor >= argument_names.len() {
                            return SizeExpr::Unknown;
                        }
                        SizeExpr::StrlenOf(argument_names[arg_cursor].clone())
                    }
                };
                arg_cursor += 1;
                total = total.add(piece);
            }
            b'c' => {
                arg_cursor += 1;
                literal_bytes_pending += 1;
            }
            _ => return SizeExpr::Unknown,
        }
    }

    if literal_bytes_pending > 0 {
        total = total.add(SizeExpr::Constant(literal_bytes_pending));
    }
    total
}

fn flatten_into(expr: SizeExpr, constant_sum: &mut u64, terms: &mut Vec<SizeExpr>) {
    match expr {
        SizeExpr::Constant(value) => {
            *constant_sum = constant_sum.saturating_add(value);
        }
        strlen @ SizeExpr::StrlenOf(_) => terms.push(strlen),
        SizeExpr::Sum(parts) => {
            for part in parts {
                flatten_into(part, constant_sum, terms);
            }
        }
        SizeExpr::Unknown => {
            unreachable!("Unknown short-circuited in SizeExpr::add");
        }
    }
}

impl fmt::Display for SizeExpr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SizeExpr::Constant(value) => write!(formatter, "{}", value),
            SizeExpr::StrlenOf(name) => write!(formatter, "strlen({})", name),
            SizeExpr::Sum(parts) => {
                let mut first = true;
                for part in parts {
                    if !first {
                        formatter.write_str(" + ")?;
                    }
                    first = false;
                    write!(formatter, "{}", part)?;
                }
                Ok(())
            }
            SizeExpr::Unknown => formatter.write_str("?"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_constants_folds_into_single_constant() {
        let result = SizeExpr::Constant(2).add(SizeExpr::Constant(3));
        assert_eq!(result, SizeExpr::Constant(5));
    }

    #[test]
    fn adding_unknown_yields_unknown() {
        assert_eq!(
            SizeExpr::Constant(2).add(SizeExpr::Unknown),
            SizeExpr::Unknown,
        );
        assert_eq!(
            SizeExpr::Unknown.add(SizeExpr::StrlenOf("path".into())),
            SizeExpr::Unknown,
        );
    }

    #[test]
    fn add_strlen_and_constant_places_constant_last_in_display() {
        let sum = SizeExpr::StrlenOf("path".into()).add(SizeExpr::Constant(1));
        assert_eq!(format!("{}", sum), "strlen(path) + 1");
    }

    #[test]
    fn add_flattens_nested_sums_and_sorts_strlen_terms_alphabetically() {
        let lhs = SizeExpr::StrlenOf("b".into()).add(SizeExpr::Constant(1));
        let rhs = SizeExpr::StrlenOf("a".into()).add(SizeExpr::Constant(2));
        let combined = lhs.add(rhs);
        assert_eq!(format!("{}", combined), "strlen(a) + strlen(b) + 3");
    }

    #[test]
    fn equality_is_invariant_under_construction_order() {
        let one = SizeExpr::StrlenOf("x".into())
            .add(SizeExpr::Constant(1))
            .add(SizeExpr::StrlenOf("y".into()));
        let two = SizeExpr::StrlenOf("y".into())
            .add(SizeExpr::StrlenOf("x".into()))
            .add(SizeExpr::Constant(1));
        assert_eq!(one, two);
    }

    #[test]
    fn plus_constant_merges_with_existing_constant_term() {
        let base = SizeExpr::StrlenOf("a".into()).add(SizeExpr::Constant(1));
        let with_nul = base.plus_constant(1);
        assert_eq!(format!("{}", with_nul), "strlen(a) + 2");
    }

    #[test]
    fn zero_plus_zero_collapses_to_constant_zero_not_an_empty_sum() {
        let zero = SizeExpr::Constant(0).add(SizeExpr::Constant(0));
        assert_eq!(zero, SizeExpr::Constant(0));
    }

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn format_empty_string_writes_zero_bytes() {
        assert_eq!(write_size_of_format("", &[]), SizeExpr::Constant(0));
    }

    #[test]
    fn format_plain_literal_counts_bytes_exactly() {
        assert_eq!(write_size_of_format("hello", &[]), SizeExpr::Constant(5),);
    }

    #[test]
    fn format_double_percent_counts_as_one_byte() {
        assert_eq!(write_size_of_format("%%", &[]), SizeExpr::Constant(1));
        assert_eq!(write_size_of_format("a%%b", &[]), SizeExpr::Constant(3));
    }

    #[test]
    fn format_percent_s_emits_strlen_of_named_argument() {
        assert_eq!(
            write_size_of_format("%s", &names(&["name"])),
            SizeExpr::StrlenOf("name".into()),
        );
    }

    #[test]
    fn format_percent_s_with_precision_emits_constant_max() {
        // %.20s caps the write at 20 bytes regardless of strlen.
        assert_eq!(
            write_size_of_format("%.20s", &names(&["name"])),
            SizeExpr::Constant(20),
        );
    }

    #[test]
    fn format_percent_s_with_only_width_still_uses_strlen() {
        // %20s pads at width 20 but does NOT truncate; max write is strlen.
        assert_eq!(
            write_size_of_format("%20s", &names(&["name"])),
            SizeExpr::StrlenOf("name".into()),
        );
    }

    /// Canonical under-sized-allocation overflow shape:
    /// `sprintf(buf, "%s#%s", prefix, name)` writes
    /// `strlen(prefix) + 1 + strlen(name)` bytes (no NUL — the caller
    /// adds that). Display puts `strlen()` terms in alphabetical order
    /// with the constant last.
    #[test]
    fn percent_s_separator_percent_s_format_matches_overflow_expression() {
        let formatted = write_size_of_format("%s#%s", &names(&["prefix", "name"]));
        assert_eq!(
            format!("{}", formatted),
            "strlen(name) + strlen(prefix) + 1"
        );
    }

    #[test]
    fn format_with_unmodeled_directive_returns_unknown() {
        assert_eq!(
            write_size_of_format("%d", &names(&["count"])),
            SizeExpr::Unknown,
        );
        assert_eq!(
            write_size_of_format("count=%u", &names(&["count"])),
            SizeExpr::Unknown,
        );
    }

    #[test]
    fn format_percent_c_consumes_argument_and_counts_one_byte() {
        // %c writes exactly one byte but still consumes one argument.
        // A following %s must then bind to the *next* argument.
        let formatted = write_size_of_format("%c%s", &names(&["ch", "tail"]));
        assert_eq!(format!("{}", formatted), "strlen(tail) + 1");
    }

    #[test]
    fn format_with_too_few_arguments_is_unknown() {
        // If the format demands more arguments than supplied, the
        // analyser cannot characterise the write — emit Unknown rather
        // than crash or assume zero.
        assert_eq!(
            write_size_of_format("%s%s", &names(&["only"])),
            SizeExpr::Unknown,
        );
    }

    #[test]
    fn format_trailing_percent_is_unknown() {
        // Malformed "...%" with no conversion — treat as Unknown.
        assert_eq!(write_size_of_format("abc%", &[]), SizeExpr::Unknown);
    }

    fn parse_function_body(parser: &mut tree_sitter::Parser, source: &str) -> tree_sitter::Tree {
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .unwrap();
        parser.parse(source, None).unwrap()
    }

    fn find_first_function_body<'a>(tree: &'a tree_sitter::Tree) -> tree_sitter::Node<'a> {
        fn walk<'a>(node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
            if node.kind() == "function_definition" {
                return node.child_by_field_name("body");
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(found) = walk(child) {
                    return Some(found);
                }
            }
            None
        }
        walk(tree.root_node()).expect("test source must contain a function")
    }

    fn allocations_in(c_source: &str) -> HashMap<String, SizeExpr> {
        let mut parser = tree_sitter::Parser::new();
        let tree = parse_function_body(&mut parser, c_source);
        let body = find_first_function_body(&tree);
        collect_allocation_sizes(body, c_source)
    }

    #[test]
    fn recognise_malloc_with_constant_size() {
        let code = "void f(void) { char *p = malloc(42); }";
        let allocations = allocations_in(code);
        assert_eq!(allocations.get("p"), Some(&SizeExpr::Constant(42)));
    }

    #[test]
    fn recognise_malloc_with_strlen_plus_one() {
        let code = "void f(const char *x) {\n    char *buf = malloc(strlen(x) + 1);\n}";
        let allocations = allocations_in(code);
        let expected = SizeExpr::StrlenOf("x".into()).add(SizeExpr::Constant(1));
        assert_eq!(allocations.get("buf"), Some(&expected));
    }

    #[test]
    fn recognise_calloc_with_two_constants_folds_to_product() {
        let code = "void f(void) { int *p = calloc(4, 8); }";
        let allocations = allocations_in(code);
        assert_eq!(allocations.get("p"), Some(&SizeExpr::Constant(32)));
    }

    #[test]
    fn calloc_with_non_constant_factor_is_unknown() {
        let code = "void f(int n) { char *p = calloc(n, 1); }";
        let allocations = allocations_in(code);
        assert_eq!(allocations.get("p"), Some(&SizeExpr::Unknown));
    }

    #[test]
    fn recognise_realloc_size_argument_only() {
        let code =
            "void f(char *old, const char *x) {\n    char *p = realloc(old, strlen(x) + 8);\n}";
        let allocations = allocations_in(code);
        let expected = SizeExpr::StrlenOf("x".into()).add(SizeExpr::Constant(8));
        assert_eq!(allocations.get("p"), Some(&expected));
    }

    #[test]
    fn recognise_assignment_to_struct_field_keyed_by_full_lhs_text() {
        // Canonical shape: a struct-field destination of an allocation
        // sized strlen(name) + 1 — the typical under-sized buffer that
        // a later sprintf overflows.
        let code = "struct dst { char *buf; };\n\
                    void f(struct dst *dst, const char *name) {\n\
                        dst->buf = malloc(strlen(name) + 1);\n\
                    }";
        let allocations = allocations_in(code);
        let expected = SizeExpr::StrlenOf("name".into()).add(SizeExpr::Constant(1));
        assert_eq!(allocations.get("dst->buf"), Some(&expected));
    }

    #[test]
    fn cast_around_allocator_is_unwrapped() {
        let code = "void f(void) { int *p = (int *)malloc(40); }";
        let allocations = allocations_in(code);
        assert_eq!(allocations.get("p"), Some(&SizeExpr::Constant(40)));
    }

    #[test]
    fn unrecognised_allocator_is_not_recorded() {
        let code = "void f(void) { char *p = my_alloc(10); }";
        let allocations = allocations_in(code);
        assert!(!allocations.contains_key("p"));
    }

    #[test]
    fn malloc_with_unknown_size_expression_records_unknown() {
        let code = "void f(int n) { char *p = malloc(n); }";
        let allocations = allocations_in(code);
        assert_eq!(allocations.get("p"), Some(&SizeExpr::Unknown));
    }

    #[test]
    fn parse_c_integer_handles_hex_and_suffixes() {
        let code = "void f(void) { char *p = malloc(0x100UL); }";
        let allocations = allocations_in(code);
        assert_eq!(allocations.get("p"), Some(&SizeExpr::Constant(256)));
    }

    /// Canonical under-sized allocation: `asprintf(&result, "%s", name)`
    /// allocates strlen(name) + 1 bytes — exactly enough for the
    /// formatted output and the NUL terminator. That allocation is
    /// the buffer a later sprintf with extra prefix bytes would
    /// overflow.
    #[test]
    fn recognise_asprintf_with_single_percent_s_yields_strlen_plus_nul() {
        let code = "int asprintf(char **, const char *, ...);\n\
                    void f(const char *name) {\n\
                        char *result;\n\
                        asprintf(&result, \"%s\", name);\n\
                    }";
        let allocations = allocations_in(code);
        let expected = SizeExpr::StrlenOf("name".into()).add(SizeExpr::Constant(1));
        assert_eq!(allocations.get("result"), Some(&expected));
    }

    #[test]
    fn recognise_asprintf_into_struct_field() {
        let code = "int asprintf(char **, const char *, ...);\n\
                    struct dst { char *buf; };\n\
                    void f(struct dst *dst, const char *x) {\n\
                        asprintf(&dst->buf, \"%s\", x);\n\
                    }";
        let allocations = allocations_in(code);
        let expected = SizeExpr::StrlenOf("x".into()).add(SizeExpr::Constant(1));
        assert_eq!(allocations.get("dst->buf"), Some(&expected));
    }

    #[test]
    fn vasprintf_destination_size_is_unknown() {
        let code = "int vasprintf(char **, const char *, void *);\n\
                    void f(const char *fmt, void *ap) {\n\
                        char *result;\n\
                        vasprintf(&result, fmt, ap);\n\
                    }";
        let allocations = allocations_in(code);
        assert_eq!(allocations.get("result"), Some(&SizeExpr::Unknown));
    }

    #[test]
    fn asprintf_with_unmodeled_directive_is_unknown_via_format_parser() {
        // %d propagates Unknown through write_size_of_format, and
        // plus_constant(1) keeps it Unknown.
        let code = "int asprintf(char **, const char *, ...);\n\
                    void f(int n) {\n\
                        char *result;\n\
                        asprintf(&result, \"n=%d\", n);\n\
                    }";
        let allocations = allocations_in(code);
        assert_eq!(allocations.get("result"), Some(&SizeExpr::Unknown));
    }

    #[test]
    fn asprintf_without_address_of_first_argument_is_skipped() {
        // If the destination isn't &something, we cannot key the size
        // back to a variable — skip rather than guess.
        let code = "int asprintf(char **, const char *, ...);\n\
                    void f(char **outptr, const char *x) {\n\
                        asprintf(outptr, \"%s\", x);\n\
                    }";
        let allocations = allocations_in(code);
        assert!(allocations.is_empty());
    }

    #[test]
    fn asprintf_with_newline_in_format_counts_one_byte_per_escape() {
        // \n is one byte after decoding — the analyser must match.
        let code = "int asprintf(char **, const char *, ...);\n\
                    void f(const char *x) {\n\
                        char *result;\n\
                        asprintf(&result, \"%s\\n\", x);\n\
                    }";
        let allocations = allocations_in(code);
        // strlen(x) + 1 byte newline + 1 byte NUL
        let expected = SizeExpr::StrlenOf("x".into()).add(SizeExpr::Constant(2));
        assert_eq!(allocations.get("result"), Some(&expected));
    }

    #[test]
    fn recognise_strdup_yields_strlen_plus_nul() {
        let code = "char *strdup(const char *);\n\
                    void f(const char *name) { char *p = strdup(name); }";
        let allocations = allocations_in(code);
        let expected = SizeExpr::StrlenOf("name".into()).add(SizeExpr::Constant(1));
        assert_eq!(allocations.get("p"), Some(&expected));
    }

    #[test]
    fn recognise_strdup_into_struct_field_keyed_by_full_lhs() {
        let code = "char *strdup(const char *);\n\
                    struct dst { char *buf; };\n\
                    void f(struct dst *dst, const char *x) {\n\
                        dst->buf = strdup(x);\n\
                    }";
        let allocations = allocations_in(code);
        let expected = SizeExpr::StrlenOf("x".into()).add(SizeExpr::Constant(1));
        assert_eq!(allocations.get("dst->buf"), Some(&expected));
    }

    #[test]
    fn recognise_strndup_with_literal_limit_yields_constant_plus_nul() {
        let code = "char *strndup(const char *, unsigned long);\n\
                    void f(const char *x) { char *p = strndup(x, 16); }";
        let allocations = allocations_in(code);
        assert_eq!(allocations.get("p"), Some(&SizeExpr::Constant(17)));
    }

    #[test]
    fn strndup_with_variable_limit_is_unknown() {
        // Without a literal for the limit, the upper bound is not
        // expressible — record Unknown so the comparison short-circuits.
        let code = "char *strndup(const char *, unsigned long);\n\
                    void f(const char *x, unsigned long n) {\n\
                        char *p = strndup(x, n);\n\
                    }";
        let allocations = allocations_in(code);
        assert_eq!(allocations.get("p"), Some(&SizeExpr::Unknown));
    }

    fn parse_full(parser: &mut tree_sitter::Parser, source: &str) -> tree_sitter::Tree {
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .unwrap();
        parser.parse(source, None).unwrap()
    }

    fn find_first_function_definition<'a>(tree: &'a tree_sitter::Tree) -> tree_sitter::Node<'a> {
        fn walk<'a>(node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
            if node.kind() == "function_definition" {
                return Some(node);
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(found) = walk(child) {
                    return Some(found);
                }
            }
            None
        }
        walk(tree.root_node()).expect("test source must contain a function definition")
    }

    #[test]
    fn summarise_function_returns_name_and_allocations() {
        let code = "void format_into(const char *name) {\n\
                        char *buf = malloc(strlen(name) + 1);\n\
                    }";
        let mut parser = tree_sitter::Parser::new();
        let tree = parse_full(&mut parser, code);
        let function_definition = find_first_function_definition(&tree);
        let (name, allocations) =
            summarise_function(function_definition, code).expect("function recognised");
        assert_eq!(name, "format_into");
        let expected = SizeExpr::StrlenOf("name".into()).add(SizeExpr::Constant(1));
        assert_eq!(allocations.get("buf"), Some(&expected));
    }

    #[test]
    fn summarise_translation_unit_collects_every_function() {
        // Two functions in one TU — the cache wants to see both so a
        // future caller of `helper` can resolve its return size.
        let code = "char *helper(const char *name) {\n\
                        return malloc(strlen(name) + 1);\n\
                    }\n\
                    void caller(const char *name) {\n\
                        char *buf = malloc(42);\n\
                        (void)buf;\n\
                        (void)name;\n\
                    }";
        let mut parser = tree_sitter::Parser::new();
        let tree = parse_full(&mut parser, code);
        let summary = summarise_translation_unit(tree.root_node(), code);
        assert!(summary.contains_key("helper"));
        assert!(summary.contains_key("caller"));
        assert_eq!(
            summary.get("caller").unwrap().get("buf"),
            Some(&SizeExpr::Constant(42))
        );
    }

    fn write_sites_in(c_source: &str) -> Vec<WriteSite> {
        let mut parser = tree_sitter::Parser::new();
        let tree = parse_function_body(&mut parser, c_source);
        let body = find_first_function_body(&tree);
        collect_write_sites(body, c_source)
    }

    #[test]
    fn sprintf_with_percent_s_records_strlen_plus_nul_write() {
        let code = "int sprintf(char *, const char *, ...);\n\
                    void f(char *buf, const char *name) {\n\
                        sprintf(buf, \"%s\", name);\n\
                    }";
        let sites = write_sites_in(code);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].destination, "buf");
        let expected = SizeExpr::StrlenOf("name".into()).add(SizeExpr::Constant(1));
        assert_eq!(sites[0].write_size, expected);
    }

    #[test]
    fn sprintf_into_struct_field_is_keyed_by_full_lhs() {
        let code = "int sprintf(char *, const char *, ...);\n\
                    struct ctx { char *buf; };\n\
                    void f(struct ctx *ctx, const char *x) {\n\
                        sprintf(ctx->buf, \"%s#%s\", x, x);\n\
                    }";
        let sites = write_sites_in(code);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].destination, "ctx->buf");
        // %s#%s writes 2*strlen(x) + 1 separator byte, then +1 NUL.
        let expected = SizeExpr::StrlenOf("x".into())
            .add(SizeExpr::StrlenOf("x".into()))
            .add(SizeExpr::Constant(2));
        assert_eq!(sites[0].write_size, expected);
    }

    #[test]
    fn sprintf_with_unmodeled_directive_records_unknown_write() {
        let code = "int sprintf(char *, const char *, ...);\n\
                    void f(char *buf, int n) {\n\
                        sprintf(buf, \"n=%d\", n);\n\
                    }";
        let sites = write_sites_in(code);
        assert_eq!(sites.len(), 1);
        // write_size_of_format returns Unknown, plus_constant(1) stays Unknown.
        assert_eq!(sites[0].write_size, SizeExpr::Unknown);
    }

    #[test]
    fn vsprintf_records_unknown_write_size() {
        let code = "int vsprintf(char *, const char *, void *);\n\
                    void f(char *buf, const char *fmt, void *ap) {\n\
                        vsprintf(buf, fmt, ap);\n\
                    }";
        let sites = write_sites_in(code);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].destination, "buf");
        assert_eq!(sites[0].write_size, SizeExpr::Unknown);
    }

    #[test]
    fn sprintf_with_non_simple_destination_is_skipped() {
        // We have no stable name to compare an allocation against —
        // skip rather than record an entry the overflow rule cannot
        // resolve.
        let code = "int sprintf(char *, const char *, ...);\n\
                    void f(char *bufs[], const char *x) {\n\
                        sprintf(bufs[0], \"%s\", x);\n\
                    }";
        let sites = write_sites_in(code);
        assert!(sites.is_empty());
    }

    #[test]
    fn strcpy_with_identifier_source_yields_strlen_plus_nul() {
        let code = "char *strcpy(char *, const char *);\n\
                    void f(char *buf, const char *name) {\n\
                        strcpy(buf, name);\n\
                    }";
        let sites = write_sites_in(code);
        assert_eq!(sites.len(), 1);
        let expected = SizeExpr::StrlenOf("name".into()).add(SizeExpr::Constant(1));
        assert_eq!(sites[0].write_size, expected);
    }

    #[test]
    fn strcpy_with_string_literal_source_uses_literal_length_plus_nul() {
        // "hello" is five bytes; the NUL makes six.
        let code = "char *strcpy(char *, const char *);\n\
                    void f(char *buf) {\n\
                        strcpy(buf, \"hello\");\n\
                    }";
        let sites = write_sites_in(code);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].write_size, SizeExpr::Constant(6));
    }

    #[test]
    fn strncpy_with_literal_count_uses_constant_size() {
        let code = "char *strncpy(char *, const char *, unsigned long);\n\
                    void f(char *buf, const char *name) {\n\
                        strncpy(buf, name, 64);\n\
                    }";
        let sites = write_sites_in(code);
        assert_eq!(sites.len(), 1);
        // strncpy writes exactly n bytes; no NUL guarantee.
        assert_eq!(sites[0].write_size, SizeExpr::Constant(64));
    }

    #[test]
    fn strncpy_with_variable_count_is_unknown() {
        let code = "char *strncpy(char *, const char *, unsigned long);\n\
                    void f(char *buf, const char *name, unsigned long n) {\n\
                        strncpy(buf, name, n);\n\
                    }";
        let sites = write_sites_in(code);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].write_size, SizeExpr::Unknown);
    }

    #[test]
    fn strcat_models_dst_plus_src_plus_nul_as_required_footprint() {
        let code = "char *strcat(char *, const char *);\n\
                    void f(char *buf, const char *name) {\n\
                        strcat(buf, name);\n\
                    }";
        let sites = write_sites_in(code);
        assert_eq!(sites.len(), 1);
        let expected = SizeExpr::StrlenOf("buf".into())
            .add(SizeExpr::StrlenOf("name".into()))
            .add(SizeExpr::Constant(1));
        assert_eq!(sites[0].write_size, expected);
    }

    #[test]
    fn memcpy_with_literal_count_uses_constant_size() {
        let code = "void *memcpy(void *, const void *, unsigned long);\n\
                    void f(char *buf, const char *src) {\n\
                        memcpy(buf, src, 128);\n\
                    }";
        let sites = write_sites_in(code);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].write_size, SizeExpr::Constant(128));
    }

    #[test]
    fn memmove_with_strlen_plus_one_uses_symbolic_size() {
        let code = "void *memmove(void *, const void *, unsigned long);\n\
                    void f(char *buf, const char *name) {\n\
                        memmove(buf, name, strlen(name) + 1);\n\
                    }";
        let sites = write_sites_in(code);
        assert_eq!(sites.len(), 1);
        let expected = SizeExpr::StrlenOf("name".into()).add(SizeExpr::Constant(1));
        assert_eq!(sites[0].write_size, expected);
    }

    #[test]
    fn memset_records_count_as_write_size() {
        let code = "void *memset(void *, int, unsigned long);\n\
                    void f(char *buf) {\n\
                        memset(buf, 0, 32);\n\
                    }";
        let sites = write_sites_in(code);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].write_size, SizeExpr::Constant(32));
    }

    #[test]
    fn unrecognised_write_call_is_not_recorded() {
        let code = "void *my_write(char *, const char *);\n\
                    void f(char *buf, const char *src) {\n\
                        my_write(buf, src);\n\
                    }";
        let sites = write_sites_in(code);
        assert!(sites.is_empty());
    }

    #[test]
    fn collect_write_sites_finds_every_call_in_function_body() {
        let code = "int sprintf(char *, const char *, ...);\n\
                    void f(char *a, char *b, const char *x) {\n\
                        sprintf(a, \"%s\", x);\n\
                        sprintf(b, \"%s%s\", x, x);\n\
                    }";
        let sites = write_sites_in(code);
        assert_eq!(sites.len(), 2);
        let destinations: Vec<_> = sites.iter().map(|s| s.destination.as_str()).collect();
        assert!(destinations.contains(&"a"));
        assert!(destinations.contains(&"b"));
    }

    #[test]
    fn constant_write_exceeding_constant_allocation_is_overflow() {
        assert!(write_exceeds_allocation(
            &SizeExpr::Constant(40),
            &SizeExpr::Constant(32),
        ));
        assert!(!write_exceeds_allocation(
            &SizeExpr::Constant(32),
            &SizeExpr::Constant(40),
        ));
        assert!(!write_exceeds_allocation(
            &SizeExpr::Constant(32),
            &SizeExpr::Constant(32),
        ));
    }

    #[test]
    fn unknown_either_side_is_not_proved_overflow() {
        assert!(!write_exceeds_allocation(
            &SizeExpr::Unknown,
            &SizeExpr::Constant(10),
        ));
        assert!(!write_exceeds_allocation(
            &SizeExpr::Constant(10),
            &SizeExpr::Unknown,
        ));
    }

    #[test]
    fn extra_strlen_terms_alone_do_not_prove_overflow() {
        // write = strlen(prefix) + strlen(name), alloc = strlen(name).
        // If prefix is empty, write == alloc — we cannot prove strict >.
        let write = SizeExpr::StrlenOf("name".into()).add(SizeExpr::StrlenOf("prefix".into()));
        let allocation = SizeExpr::StrlenOf("name".into());
        assert!(!write_exceeds_allocation(&write, &allocation));
    }

    #[test]
    fn canonical_asprintf_then_sprintf_pattern_is_detected_as_overflow() {
        // alloc = strlen(name) + 1, write = strlen(name) + strlen(prefix) + 2
        // The strlen multiset of write covers alloc's, and the constants
        // differ in the right direction — this is the smoking-gun shape.
        let allocation = SizeExpr::StrlenOf("name".into()).add(SizeExpr::Constant(1));
        let write = SizeExpr::StrlenOf("name".into())
            .add(SizeExpr::StrlenOf("prefix".into()))
            .add(SizeExpr::Constant(2));
        assert!(write_exceeds_allocation(&write, &allocation));
    }

    #[test]
    fn constant_write_into_strlen_allocation_is_not_proved_overflow() {
        // write = 5, alloc = strlen(name) + 1.
        // For long enough name, alloc dominates — we cannot prove
        // overflow without bounding strlen(name).
        let write = SizeExpr::Constant(5);
        let allocation = SizeExpr::StrlenOf("name".into()).add(SizeExpr::Constant(1));
        assert!(!write_exceeds_allocation(&write, &allocation));
    }

    fn run_scan(code: &str) -> Vec<HeapOverflowFinding> {
        scan_heap_overflows(code, "test.c")
    }

    #[test]
    fn scan_heap_overflows_finds_malloc_then_strcpy_with_long_literal() {
        // malloc(8) + strcpy(buf, "very long literal") — 18 bytes (17 + NUL)
        // written into 8-byte buffer.
        let code = "char *malloc(unsigned long);\n\
                    char *strcpy(char *, const char *);\n\
                    void f(void) {\n\
                        char *buf = malloc(8);\n\
                        strcpy(buf, \"very long literal\");\n\
                    }";
        let findings = run_scan(code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].destination, "buf");
        assert_eq!(findings[0].allocation_size, SizeExpr::Constant(8));
        assert_eq!(findings[0].write_size, SizeExpr::Constant(18));
        // strcpy is on line 5; column at start of call expression.
        assert_eq!(findings[0].line, 5);
        assert!(findings[0].snippet.starts_with("strcpy(buf"));
    }

    #[test]
    fn scan_heap_overflows_finds_asprintf_then_sprintf_overflow() {
        // asprintf allocates strlen(name) + 1, sprintf writes
        // strlen(prefix) + 1 + strlen(name) + 1 NUL.
        let code = "int asprintf(char **, const char *, ...);\n\
                    int sprintf(char *, const char *, ...);\n\
                    void f(const char *prefix, const char *name) {\n\
                        char *buf;\n\
                        asprintf(&buf, \"%s\", name);\n\
                        sprintf(buf, \"%s#%s\", prefix, name);\n\
                    }";
        let findings = run_scan(code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].destination, "buf");
    }

    #[test]
    fn scan_heap_overflows_finds_calloc_then_memset_overflow() {
        // calloc(4, 8) = 32 bytes; memset writes 40 bytes.
        let code = "void *calloc(unsigned long, unsigned long);\n\
                    void *memset(void *, int, unsigned long);\n\
                    void f(void) {\n\
                        char *buf = calloc(4, 8);\n\
                        memset(buf, 0, 40);\n\
                    }";
        let findings = run_scan(code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].allocation_size, SizeExpr::Constant(32));
        assert_eq!(findings[0].write_size, SizeExpr::Constant(40));
    }

    #[test]
    fn scan_heap_overflows_reports_nothing_when_sizes_match() {
        // malloc(strlen(name) + 1) + strcpy(buf, name) — exact fit.
        let code = "char *malloc(unsigned long);\n\
                    char *strcpy(char *, const char *);\n\
                    unsigned long strlen(const char *);\n\
                    void f(const char *name) {\n\
                        char *buf = malloc(strlen(name) + 1);\n\
                        strcpy(buf, name);\n\
                    }";
        let findings = run_scan(code);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_heap_overflows_isolates_findings_per_function() {
        // First function has an overflow; second is clean. Both buffers
        // are local — names must not leak across function boundaries.
        let code = "char *malloc(unsigned long);\n\
                    char *strcpy(char *, const char *);\n\
                    void bad(void) {\n\
                        char *buf = malloc(4);\n\
                        strcpy(buf, \"longer\");\n\
                    }\n\
                    void good(void) {\n\
                        char *buf = malloc(64);\n\
                        strcpy(buf, \"short\");\n\
                    }";
        let findings = run_scan(code);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].snippet.contains("longer"));
    }

    #[test]
    fn substitute_parameters_swaps_strlen_argument() {
        let template = SizeExpr::StrlenOf("name".into()).add(SizeExpr::Constant(1));
        let result = substitute_parameters(
            &template,
            &["name".to_string()],
            &["caller_name".to_string()],
        );
        let expected = SizeExpr::StrlenOf("caller_name".into()).add(SizeExpr::Constant(1));
        assert_eq!(result, expected);
    }

    #[test]
    fn substitute_parameters_preserves_unrelated_strlen_terms() {
        // strlen(other) is not a parameter of the function — leave it
        // alone rather than mis-substituting.
        let template = SizeExpr::StrlenOf("other".into()).add(SizeExpr::Constant(1));
        let result = substitute_parameters(
            &template,
            &["name".to_string()],
            &["caller_arg".to_string()],
        );
        let expected = SizeExpr::StrlenOf("other".into()).add(SizeExpr::Constant(1));
        assert_eq!(result, expected);
    }

    #[test]
    fn build_function_summary_cache_records_returned_allocation() {
        let code = "char *malloc(unsigned long);\n\
                    unsigned long strlen(const char *);\n\
                    char *helper(const char *name) {\n\
                        return malloc(strlen(name) + 1);\n\
                    }";
        let mut parser = tree_sitter::Parser::new();
        let tree = parse_full(&mut parser, code);
        let cache = build_function_summary_cache(tree.root_node(), code);
        let summary = cache.get("helper").expect("helper must be summarised");
        assert_eq!(summary.parameter_names, vec!["name".to_string()]);
        let expected = SizeExpr::StrlenOf("name".into()).add(SizeExpr::Constant(1));
        assert_eq!(summary.return_size, expected);
    }

    #[test]
    fn build_function_summary_cache_skips_non_allocator_returns() {
        // helper returns a non-allocator pointer — we must not invent
        // a size, just leave its return_size Unknown.
        let code = "char *helper(char *p) { return p; }";
        let mut parser = tree_sitter::Parser::new();
        let tree = parse_full(&mut parser, code);
        let cache = build_function_summary_cache(tree.root_node(), code);
        let summary = cache.get("helper").expect("helper summarised");
        assert_eq!(summary.return_size, SizeExpr::Unknown);
    }

    #[test]
    fn build_function_summary_cache_returns_unknown_for_disagreeing_returns() {
        // Two returns of different sizes — the cache must not pick one
        // arbitrarily.
        let code = "char *malloc(unsigned long);\n\
                    char *helper(int branch) {\n\
                        if (branch) { return malloc(8); }\n\
                        return malloc(16);\n\
                    }";
        let mut parser = tree_sitter::Parser::new();
        let tree = parse_full(&mut parser, code);
        let cache = build_function_summary_cache(tree.root_node(), code);
        let summary = cache.get("helper").expect("helper summarised");
        assert_eq!(summary.return_size, SizeExpr::Unknown);
    }

    #[test]
    fn summarise_function_recognises_return_via_assignment_from_asprintf() {
        // Trigger shape: `out` is declared without initialiser, populated
        // by asprintf as an out-parameter, then returned. The error path
        // `return 0` must not collapse the result to Unknown.
        let code = "int asprintf(char **, const char *, ...);\n\
                    char *make_name(const char *base) {\n\
                        char *out;\n\
                        int ret = asprintf(&out, \"%s\", base);\n\
                        if (ret < 0) return 0;\n\
                        return out;\n\
                    }";
        let mut parser = tree_sitter::Parser::new();
        let tree = parse_full(&mut parser, code);
        let cache = build_function_summary_cache(tree.root_node(), code);
        let summary = cache.get("make_name").expect("make_name summarised");
        let expected = SizeExpr::StrlenOf("base".into()).add(SizeExpr::Constant(1));
        assert_eq!(summary.return_size, expected);
    }

    #[test]
    fn summarise_function_recognises_return_via_assignment_from_malloc() {
        // Variant of the trigger shape: the populating site is a direct
        // assignment `out = malloc(...)` rather than an out-parameter.
        let code = "char *malloc(unsigned long);\n\
                    unsigned long strlen(const char *);\n\
                    char *make_buf(const char *base) {\n\
                        char *out;\n\
                        out = malloc(strlen(base) + 1);\n\
                        return out;\n\
                    }";
        let mut parser = tree_sitter::Parser::new();
        let tree = parse_full(&mut parser, code);
        let cache = build_function_summary_cache(tree.root_node(), code);
        let summary = cache.get("make_buf").expect("make_buf summarised");
        let expected = SizeExpr::StrlenOf("base".into()).add(SizeExpr::Constant(1));
        assert_eq!(summary.return_size, expected);
    }

    #[test]
    fn summarise_function_unknown_when_assignment_disagrees() {
        // Two non-error populating sites with different sizes must
        // collapse to Unknown — "miss rather than misreport".
        let code = "char *malloc(unsigned long);\n\
                    char *pick(int branch) {\n\
                        char *out;\n\
                        out = malloc(4);\n\
                        out = malloc(8);\n\
                        return out;\n\
                    }";
        let mut parser = tree_sitter::Parser::new();
        let tree = parse_full(&mut parser, code);
        let cache = build_function_summary_cache(tree.root_node(), code);
        let summary = cache.get("pick").expect("pick summarised");
        assert_eq!(summary.return_size, SizeExpr::Unknown);
    }

    #[test]
    fn cross_function_helper_resolves_caller_allocation_through_cache() {
        // helper allocates strlen(name) + 1; caller passes a *different*
        // identifier and writes a long literal that exceeds it.
        // The substitution must rename the strlen argument to the
        // caller's actual variable.
        let code = "char *malloc(unsigned long);\n\
                    unsigned long strlen(const char *);\n\
                    char *strcpy(char *, const char *);\n\
                    char *helper(const char *name) {\n\
                        return malloc(strlen(name) + 1);\n\
                    }\n\
                    void caller(const char *user_input) {\n\
                        char *buf = helper(user_input);\n\
                        strcpy(buf, \"longer than user input might be\");\n\
                    }";
        let mut parser = tree_sitter::Parser::new();
        let tree = parse_full(&mut parser, code);
        let cache = build_function_summary_cache(tree.root_node(), code);
        let summary = cache.get("helper").unwrap();
        let argument_texts = vec!["user_input".to_string()];
        let resolved = substitute_parameters(
            &summary.return_size,
            &summary.parameter_names,
            &argument_texts,
        );
        let expected = SizeExpr::StrlenOf("user_input".into()).add(SizeExpr::Constant(1));
        assert_eq!(resolved, expected);
    }

    #[test]
    fn scan_heap_overflows_resolves_caller_buffer_through_helper() {
        // End-to-end: the caller's buf is sized by helper(); the
        // strcpy with a 31-byte literal overflows strlen(user_input)+1
        // only when constants dominate, which they do here because
        // the write side has the same StrlenOf term plus a larger
        // constant.
        let code = "char *malloc(unsigned long);\n\
                    unsigned long strlen(const char *);\n\
                    char *strcpy(char *, const char *);\n\
                    char *helper(const char *name) {\n\
                        return malloc(strlen(name));\n\
                    }\n\
                    void caller(const char *user_input) {\n\
                        char *buf = helper(user_input);\n\
                        strcpy(buf, user_input);\n\
                    }";
        // helper returns strlen(name); caller writes strlen(user_input) + 1
        // (the NUL). After substitution, alloc = strlen(user_input),
        // write = strlen(user_input) + 1. write_constant > alloc_constant
        // and strlen multisets match — overflow.
        let findings = scan_heap_overflows(code, "cross.c");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].destination, "buf");
    }

    #[test]
    fn detects_calloc_with_wrapping_literal_product() {
        let code = "void *calloc(unsigned long, unsigned long);\n\
                    void f(void) { void *p = calloc(0xFFFFFFFFFFFFFFFF, 2); }";
        let findings = scan_constant_overflows(code, "wrap.c");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].allocator, "calloc");
        assert_eq!(findings[0].operator, "*");
    }

    #[test]
    fn detects_malloc_with_wrapping_literal_multiplication() {
        let code = "void *malloc(unsigned long);\n\
                    void f(void) { void *p = malloc(0xFFFFFFFFFFFFFFFF * 2); }";
        let findings = scan_constant_overflows(code, "wrap.c");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].allocator, "malloc");
        assert_eq!(findings[0].operator, "*");
    }

    #[test]
    fn detects_malloc_with_wrapping_literal_addition() {
        let code = "void *malloc(unsigned long);\n\
                    void f(void) { void *p = malloc(0xFFFFFFFFFFFFFFFF + 1); }";
        let findings = scan_constant_overflows(code, "wrap.c");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].operator, "+");
    }

    #[test]
    fn does_not_fire_on_safe_constant_calloc() {
        let code = "void *calloc(unsigned long, unsigned long);\n\
                    void f(void) { void *p = calloc(4, 8); }";
        let findings = scan_constant_overflows(code, "ok.c");
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_fire_on_non_constant_malloc_argument() {
        // Variable operand — out of scope for the literal-only rule.
        let code = "void *malloc(unsigned long);\n\
                    unsigned long strlen(const char *);\n\
                    void f(const char *name) {\n\
                        void *p = malloc(strlen(name) * 4);\n\
                    }";
        let findings = scan_constant_overflows(code, "nonconst.c");
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_fire_on_realloc_with_safe_constants() {
        let code = "void *realloc(void *, unsigned long);\n\
                    void f(void *p) { void *q = realloc(p, 8 * 16); }";
        let findings = scan_constant_overflows(code, "ok.c");
        assert!(findings.is_empty());
    }

    #[test]
    fn sizeof_mul_detects_malloc_with_variable_times_sizeof() {
        let code = "void *malloc(unsigned long);\n\
                    struct foo { int x; };\n\
                    void f(unsigned long n) {\n\
                        void *p = malloc(n * sizeof(struct foo));\n\
                    }";
        let findings = scan_sizeof_multiplications(code, "vuln.c");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].allocator, "malloc");
        assert_eq!(findings[0].variable_operand, "n");
        assert!(findings[0].sizeof_operand.contains("sizeof"));
    }

    #[test]
    fn sizeof_mul_detects_calloc_with_variable_count() {
        let code = "void *calloc(unsigned long, unsigned long);\n\
                    void f(unsigned long n) {\n\
                        void *p = calloc(n, sizeof(int));\n\
                    }";
        let findings = scan_sizeof_multiplications(code, "vuln.c");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].variable_operand, "n");
    }

    #[test]
    fn sizeof_mul_handles_sizeof_on_either_side() {
        // sizeof(T) * n should match the same as n * sizeof(T).
        let code = "void *malloc(unsigned long);\n\
                    void f(unsigned long n) {\n\
                        void *p = malloc(sizeof(int) * n);\n\
                    }";
        let findings = scan_sizeof_multiplications(code, "vuln.c");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].variable_operand, "n");
    }

    #[test]
    fn sizeof_mul_skips_constant_count() {
        // 4 * sizeof(int) — both literal, no overflow risk.
        let code = "void *malloc(unsigned long);\n\
                    void f(void) { void *p = malloc(4 * sizeof(int)); }";
        let findings = scan_sizeof_multiplications(code, "ok.c");
        assert!(findings.is_empty());
    }

    #[test]
    fn sizeof_mul_skips_call_without_sizeof() {
        // n * 4 — no sizeof, out of scope for this rule.
        let code = "void *malloc(unsigned long);\n\
                    void f(unsigned long n) { void *p = malloc(n * 4); }";
        let findings = scan_sizeof_multiplications(code, "ok.c");
        assert!(findings.is_empty());
    }

    #[test]
    fn sizeof_mul_skips_calloc_with_two_constants() {
        let code = "void *calloc(unsigned long, unsigned long);\n\
                    void f(void) { void *p = calloc(8, sizeof(int)); }";
        let findings = scan_sizeof_multiplications(code, "ok.c");
        assert!(findings.is_empty());
    }

    #[test]
    fn format_with_length_modifier_on_percent_s_still_uses_strlen() {
        // glibc accepts %ls (wide string) but we model it as Unknown via
        // the conversion-char check — `l` is consumed as a length modifier,
        // then `s` is the conversion. Without a wide-char strlen model this
        // would over-report; ensure ordinary "%s" with no modifier still
        // works as the baseline.
        let plain = write_size_of_format("%s", &names(&["x"]));
        assert_eq!(plain, SizeExpr::StrlenOf("x".into()));
        // %ls then binds the conversion `s` after skipping `l`. We treat
        // it the same as %s right now — that is a known approximation;
        // wide-string accuracy is out of scope for this patch.
        let with_l = write_size_of_format("%ls", &names(&["x"]));
        assert_eq!(with_l, SizeExpr::StrlenOf("x".into()));
    }

    #[test]
    fn null_context_never_resolves_a_callee() {
        // The plumbing contract: NullContext must refuse every lookup so
        // the analyser short-circuits to Unknown rather than guessing.
        // A future CrossFileContext impl that *does* resolve must do so
        // only when a single definition is unambiguous; this test guards
        // the safe baseline.
        let ctx = NullContext;
        assert!(ctx.locate_function("anything", "caller.c").is_none());
        assert!(ctx.locate_function("", "").is_none());
    }

    /// Test-only resolver: returns a fixed `(file_path, source)` for
    /// every name listed in its `entries`. Used to drive
    /// [`scan_heap_overflows_with_context`] across synthetic file
    /// boundaries without standing up a full call graph.
    struct MockContext {
        entries: std::collections::HashMap<String, (String, String)>,
    }

    impl MockContext {
        fn with(name: &str, file_path: &str, source: &str) -> Self {
            let mut entries = std::collections::HashMap::new();
            entries.insert(
                name.to_string(),
                (file_path.to_string(), source.to_string()),
            );
            MockContext { entries }
        }
    }

    impl CrossFileContext for MockContext {
        fn locate_function(&self, name: &str, _caller_file: &str) -> Option<FunctionLocation> {
            self.entries
                .get(name)
                .map(|(file_path, source)| FunctionLocation {
                    file_path: file_path.clone(),
                    source: source.clone(),
                })
        }
    }

    #[test]
    fn scan_heap_overflows_with_context_detects_cross_translation_unit_overflow() {
        // The whole point of this patch series: an allocator helper in
        // one .c file paired with an over-sized write in another must
        // surface as a CWE-122 finding. With per-TU-only resolution
        // (NullContext) the same scan returns nothing — captured by
        // the second half of this test.
        let helper_source = "char *small_buf(void) {\n    return malloc(4);\n}\n";
        let caller_source =
            "void use(void) {\n    char *p = small_buf();\n    strcpy(p, \"hello world\");\n}\n";

        let ctx = MockContext::with("small_buf", "lib/helper.c", helper_source);
        let cross_findings = scan_heap_overflows_with_context(caller_source, "util/caller.c", &ctx);
        assert_eq!(
            cross_findings.len(),
            1,
            "exactly one cross-TU CWE-122 finding expected, got {:?}",
            cross_findings,
        );
        assert_eq!(cross_findings[0].file_path, "util/caller.c");

        // Baseline: with NullContext the analyser cannot see the helper
        // and so emits no finding. Guards against the resolver
        // accidentally becoming a no-op in future refactors.
        let baseline =
            scan_heap_overflows_with_context(caller_source, "util/caller.c", &NullContext);
        assert!(
            baseline.is_empty(),
            "NullContext path must remain per-TU only, got {:?}",
            baseline,
        );
    }

    #[test]
    fn cross_file_resolver_does_not_infinite_loop_on_recursive_helper() {
        // A helper that calls itself must not send the resolver into a
        // cycle. The InProgress marker turns the recursive lookup into
        // an Unresolvable result; compute_return_size then sees a
        // mixed-shape return set and yields Unknown, so the caller
        // ends up with no resolved allocation size — no finding, no
        // hang, no panic.
        let helper_source = "char *loops(int n) {\n    if (n == 0) return malloc(1);\n    return loops(n - 1);\n}\n";
        let caller_source = "void use(void) {\n    char *p = loops(3);\n    strcpy(p, \"x\");\n}\n";

        let ctx = MockContext::with("loops", "lib/helper.c", helper_source);
        let findings = scan_heap_overflows_with_context(caller_source, "util/caller.c", &ctx);
        assert!(
            findings.is_empty(),
            "recursive helper must short-circuit to Unknown, got {:?}",
            findings,
        );
    }

    #[test]
    fn engine_scan_with_context_emits_cwe_122_for_return_via_assignment_shape() {
        // End-to-end: the helper allocates via `asprintf(&out, "%s", base)`
        // and returns `out`; the caller builds `"%s#%s"` into that buffer,
        // overflowing by the prefix plus the separator. Until patch 26 the
        // helper summarised as Unknown — the cross-TU pipeline ran but had
        // no size to compare against. This test guards that the resolver
        // now sees through the assignment.
        let helper_source = "int asprintf(char **, const char *, ...);\n\
                             char *make_name(const char *base) {\n\
                                 char *out;\n\
                                 int ret = asprintf(&out, \"%s\", base);\n\
                                 if (ret < 0) return 0;\n\
                                 return out;\n\
                             }\n";
        let caller_source = "char *make_name(const char *);\n\
                             int sprintf(char *, const char *, ...);\n\
                             void use(const char *base, const char *prefix) {\n\
                                 char *name = make_name(base);\n\
                                 sprintf(name, \"%s#%s\", prefix, base);\n\
                             }\n";

        let ctx = MockContext::with("make_name", "lib/helper.c", helper_source);
        let cross_findings = scan_heap_overflows_with_context(caller_source, "util/caller.c", &ctx);
        assert!(
            cross_findings
                .iter()
                .any(|f| f.file_path == "util/caller.c"),
            "expected at least one CWE-122 finding for util/caller.c, got {:?}",
            cross_findings,
        );

        // Baseline: per-TU only (NullContext) cannot see the helper, so
        // the shape must remain undetectable without context. Guards the
        // resolver from accidentally becoming a no-op.
        let baseline =
            scan_heap_overflows_with_context(caller_source, "util/caller.c", &NullContext);
        assert!(
            !baseline.iter().any(|f| f.file_path == "util/caller.c"),
            "NullContext path must not fire for return-via-assignment shape, got {:?}",
            baseline,
        );
    }

    #[test]
    fn null_deref_calloc_then_strcpy_without_check_is_flagged() {
        let code = "\
unsigned long strlen(const char *);
void *calloc(unsigned long, unsigned long);
char *strcpy(char *, const char *);

void missing_check(const char *src) {
    unsigned long n = strlen(src) + 1;
    char *buf = calloc(1, n);
    strcpy(buf, src);
}
";
        let findings = scan_null_deref_after_alloc(code, "missing.c");
        assert_eq!(findings.len(), 1, "expected one finding, got {findings:?}");
        let finding = &findings[0];
        assert_eq!(finding.pointer, "buf");
        assert_eq!(finding.allocator, "calloc");
    }

    #[test]
    fn null_deref_malloc_then_check_then_strcpy_is_not_flagged() {
        let code = "\
void *malloc(unsigned long);
char *strcpy(char *, const char *);

void has_check(unsigned long n, const char *src) {
    char *buf = malloc(n);
    if (!buf) return;
    strcpy(buf, src);
}
";
        let findings = scan_null_deref_after_alloc(code, "checked.c");
        assert!(
            findings.is_empty(),
            "expected no findings (early-leave guards use), got {findings:?}"
        );
    }

    #[test]
    fn null_deref_eq_null_check_then_use_is_not_flagged() {
        let code = "\
void *malloc(unsigned long);
char *strcpy(char *, const char *);

void has_check(unsigned long n, const char *src) {
    char *buf = malloc(n);
    if (buf == NULL) return;
    strcpy(buf, src);
}
";
        let findings = scan_null_deref_after_alloc(code, "eq_null.c");
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:?}"
        );
    }

    #[test]
    fn null_deref_use_inside_truthy_block_is_not_flagged() {
        let code = "\
void *malloc(unsigned long);
char *strcpy(char *, const char *);

void guarded_block(unsigned long n, const char *src) {
    char *buf = malloc(n);
    if (buf) {
        strcpy(buf, src);
    }
}
";
        let findings = scan_null_deref_after_alloc(code, "guarded.c");
        assert!(
            findings.is_empty(),
            "expected no findings (use inside if(buf) block is guarded), got {findings:?}"
        );
    }

    #[test]
    fn null_deref_strdup_without_check_is_flagged() {
        let code = "\
char *strdup(const char *);
unsigned long strlen(const char *);

void leak(const char *src) {
    char *copy = strdup(src);
    unsigned long len = strlen(copy);
    (void)len;
}
";
        let findings = scan_null_deref_after_alloc(code, "leak.c");
        assert_eq!(findings.len(), 1, "expected one finding, got {findings:?}");
        assert_eq!(findings[0].allocator, "strdup");
        assert_eq!(findings[0].pointer, "copy");
    }

    #[test]
    fn null_deref_alloc_in_assignment_then_deref_is_flagged() {
        let code = "\
void *malloc(unsigned long);

void via_assignment(char *out, unsigned long n) {
    out = malloc(n);
    *out = 0;
}
";
        let findings = scan_null_deref_after_alloc(code, "assign.c");
        assert_eq!(findings.len(), 1, "expected one finding, got {findings:?}");
        assert_eq!(findings[0].allocator, "malloc");
        assert_eq!(findings[0].pointer, "out");
    }

    #[test]
    fn null_deref_no_allocator_emits_nothing() {
        let code = "\
char *strcpy(char *, const char *);

void no_alloc(char *buf, const char *src) {
    strcpy(buf, src);
}
";
        let findings = scan_null_deref_after_alloc(code, "noalloc.c");
        assert!(
            findings.is_empty(),
            "expected no findings (no allocator call), got {findings:?}"
        );
    }

    #[test]
    fn null_deref_goto_cleanup_is_a_recognised_leave() {
        let code = "\
void *malloc(unsigned long);
char *strcpy(char *, const char *);

void with_goto(unsigned long n, const char *src) {
    char *buf = malloc(n);
    if (!buf) goto fail;
    strcpy(buf, src);
fail:
    return;
}
";
        let findings = scan_null_deref_after_alloc(code, "goto.c");
        assert!(
            findings.is_empty(),
            "expected no findings (goto cleanup counts as leave), got {findings:?}"
        );
    }
}
