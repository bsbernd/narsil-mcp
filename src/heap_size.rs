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
    pub fn add(self, other: Self) -> Self {
        if matches!(self, SizeExpr::Unknown) || matches!(other, SizeExpr::Unknown) {
            return SizeExpr::Unknown;
        }

        let mut constant_sum: u64 = 0;
        let mut symbolic_terms: Vec<SizeExpr> = Vec::new();
        flatten_into(self, &mut constant_sum, &mut symbolic_terms);
        flatten_into(other, &mut constant_sum, &mut symbolic_terms);

        symbolic_terms.sort_by(|left, right| left.to_string().cmp(&right.to_string()));
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
    let mut out = HashMap::new();
    collect_into(function_body, source, &mut out);
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

fn collect_into(node: Node<'_>, source: &str, out: &mut HashMap<String, SizeExpr>) {
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
                            if let Some(size) = recognise_allocator_call(rhs, source) {
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
                    if let Some(size) = recognise_allocator_call(rhs, source) {
                        out.insert(name, size);
                    }
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_into(child, source, out);
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
    let cleaned = text.trim_end_matches(|byte: char| matches!(byte, 'u' | 'U' | 'l' | 'L'));
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
}
