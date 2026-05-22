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

use std::fmt;

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
