//! Symbol types and classification for code intelligence

use serde::{Deserialize, Serialize};

/// Set of analysis backends that confirmed a symbol or call edge.
///
/// One `u8`, one bit per backend (no `bitflags` crate — matches the project's
/// raw+named-mask convention). Carried by both [`Symbol`] and the call graph's
/// `CallEdge`, so every datum records *which* backends saw it. When backends
/// disagree on a location or on metadata, priority ([`SourceSet::rank`])
/// resolves the conflict: `clangd > ccls > tree-sitter > gtags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SourceSet(u8);

impl SourceSet {
    pub const TREE_SITTER: Self = Self(1 << 0);
    pub const CLANGD: Self = Self(1 << 1);
    pub const CCLS: Self = Self(1 << 2);
    pub const GTAGS: Self = Self(1 << 3);

    /// Empty set — no confirmer.
    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// serde default for the legacy on-disk format that predates provenance.
    fn tree_sitter_default() -> Self {
        Self::TREE_SITTER
    }

    /// Add every backend in `other`.
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// True when every bit of `other` is present.
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Number of distinct confirmers.
    pub fn count(self) -> u32 {
        self.0.count_ones()
    }

    /// Priority of a single backend: `clangd > ccls > tree-sitter > gtags`.
    /// The empty set and any unknown bit rank 0. Values are relative only —
    /// they order conflict resolution, not storage (the bit positions do that).
    pub fn rank(self) -> u8 {
        match self {
            Self::CLANGD => 4,
            Self::CCLS => 3,
            Self::TREE_SITTER => 2,
            Self::GTAGS => 1,
            _ => 0,
        }
    }

    /// The highest-priority single backend in the set (empty set stays empty).
    pub fn highest(self) -> Self {
        [Self::CLANGD, Self::CCLS, Self::TREE_SITTER, Self::GTAGS]
            .into_iter()
            .find(|bit| self.contains(*bit))
            .unwrap_or_else(Self::empty)
    }

    /// Human labels for each member, highest priority first.
    pub fn labels(self) -> Vec<&'static str> {
        [
            (Self::CLANGD, "clangd"),
            (Self::CCLS, "ccls"),
            (Self::TREE_SITTER, "tree-sitter"),
            (Self::GTAGS, "gtags"),
        ]
        .into_iter()
        .filter(|(bit, _)| self.contains(*bit))
        .map(|(_, label)| label)
        .collect()
    }
}

/// A backend's reported line for a symbol/edge whose canonical line came from a
/// higher-priority backend. Retained so a location disagreement reaches the
/// consumer instead of being hidden behind the priority winner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLine {
    pub source: SourceSet,
    pub line: usize,
}

/// The kind of symbol (data structure, function, etc.)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolKind {
    // Data structures
    Struct,
    Class,
    Enum,
    Interface,
    Trait,
    TypeAlias,

    // Functions and methods
    Function,
    Method,
    Constructor,

    // Modules and namespaces
    Module,
    Namespace,
    Package,

    // Values
    Constant,
    Variable,
    Field,
    Parameter,

    // Special
    Implementation,
    Macro,
    Unknown,
}

impl SymbolKind {
    /// Check if this is a data structure type
    pub fn is_data_structure(&self) -> bool {
        matches!(
            self,
            SymbolKind::Struct
                | SymbolKind::Class
                | SymbolKind::Enum
                | SymbolKind::Interface
                | SymbolKind::Trait
                | SymbolKind::TypeAlias
        )
    }

    /// Check if this is a callable
    pub fn is_callable(&self) -> bool {
        matches!(
            self,
            SymbolKind::Function | SymbolKind::Method | SymbolKind::Constructor
        )
    }

    /// Get icon for display
    pub fn icon(&self) -> &'static str {
        match self {
            SymbolKind::Struct => "ðŸ“¦",
            SymbolKind::Class => "ðŸ›ï¸",
            SymbolKind::Enum => "ðŸ“‹",
            SymbolKind::Interface => "ðŸ“œ",
            SymbolKind::Trait => "ðŸ”§",
            SymbolKind::TypeAlias => "ðŸ·ï¸",
            SymbolKind::Function => "âš¡",
            SymbolKind::Method => "ðŸ”¹",
            SymbolKind::Constructor => "ðŸ”¨",
            SymbolKind::Module => "ðŸ“",
            SymbolKind::Namespace => "ðŸ“‚",
            SymbolKind::Package => "ðŸ“¦",
            SymbolKind::Constant => "ðŸ”’",
            SymbolKind::Variable => "ðŸ’¾",
            SymbolKind::Field => "ðŸ”·",
            SymbolKind::Parameter => "ðŸ“¥",
            SymbolKind::Implementation => "âš™ï¸",
            SymbolKind::Macro => "ðŸŽ¯",
            SymbolKind::Unknown => "â“",
        }
    }
}

/// A symbol extracted from source code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    /// The symbol name
    pub name: String,

    /// The kind of symbol
    pub kind: SymbolKind,

    /// File path relative to repository root
    pub file_path: String,

    /// Starting line number (1-indexed)
    pub start_line: usize,

    /// Ending line number (1-indexed, inclusive)
    pub end_line: usize,

    /// The symbol signature (e.g., function signature)
    pub signature: Option<String>,

    /// Fully qualified name (e.g., module::ClassName::method)
    pub qualified_name: Option<String>,

    /// Documentation comment
    pub doc_comment: Option<String>,

    /// Backends that confirmed this symbol's existence. `start_line`/`end_line`
    /// and the metadata fields hold the values from the highest-priority
    /// confirmer in this set.
    #[serde(default = "SourceSet::tree_sitter_default")]
    pub confirmed_by: SourceSet,

    /// Confirmers whose reported line differs from `start_line`. Empty when all
    /// agree (the common case -> zero overhead). Retained so the disagreement
    /// reaches the consumer instead of being hidden behind the priority winner.
    #[serde(default)]
    pub line_conflicts: Vec<SourceLine>,
}

impl Symbol {
    /// Get the display name with kind icon
    pub fn display_name(&self) -> String {
        format!("{} {}", self.kind.icon(), self.name)
    }

    /// Get location string
    pub fn location(&self) -> String {
        format!("{}:{}-{}", self.file_path, self.start_line, self.end_line)
    }

    /// Get line count
    pub fn line_count(&self) -> usize {
        self.end_line.saturating_sub(self.start_line) + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_kind_classification() {
        assert!(SymbolKind::Struct.is_data_structure());
        assert!(SymbolKind::Class.is_data_structure());
        assert!(!SymbolKind::Function.is_data_structure());

        assert!(SymbolKind::Function.is_callable());
        assert!(SymbolKind::Method.is_callable());
        assert!(!SymbolKind::Struct.is_callable());
    }

    #[test]
    fn test_symbol_display() {
        let sym = Symbol {
            name: "MyStruct".to_string(),
            kind: SymbolKind::Struct,
            file_path: "src/lib.rs".to_string(),
            start_line: 10,
            end_line: 20,
            signature: Some("pub struct MyStruct".to_string()),
            qualified_name: Some("crate::MyStruct".to_string()),
            doc_comment: None,
            confirmed_by: SourceSet::TREE_SITTER,
            line_conflicts: Vec::new(),
        };

        assert_eq!(sym.location(), "src/lib.rs:10-20");
        assert_eq!(sym.line_count(), 11);
    }
}
