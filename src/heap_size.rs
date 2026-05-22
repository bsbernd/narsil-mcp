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
}
