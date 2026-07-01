//! Linux `SYSCALL_DEFINEn` recognition.
//!
//! tree-sitter-c cannot see `SYSCALL_DEFINE6(name, type, arg, ...) { body }` as a
//! `function_definition`: the declarator is a macro call, so the grammar parses it
//! as two siblings — an `expression_statement` wrapping a `call_expression`
//! (`SYSCALL_DEFINE6(...)`, with the arg types recovered as `ERROR` nodes) and the
//! `{ body }` as a following `compound_statement`. The kernel entry point and every
//! call in its body are therefore absent from the call graph and the symbol index.
//!
//! These helpers recognise that stable error-recovery shape so both subsystems can
//! synthesise a normal function named after the syscall (the macro's first argument).

use tree_sitter::Node;

/// True for `SYSCALL_DEFINE<n>` / `COMPAT_SYSCALL_DEFINE<n>` (n a single digit 0-9),
/// the macro spelling that opens a syscall body.
pub(crate) fn is_syscall_define_macro(name: &str) -> bool {
    for prefix in ["SYSCALL_DEFINE", "COMPAT_SYSCALL_DEFINE"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            return rest.len() == 1 && rest.as_bytes()[0].is_ascii_digit();
        }
    }
    false
}

/// If `call` is a `SYSCALL_DEFINE` invocation, return the declared syscall name —
/// the macro's first argument. `SYSCALL_DEFINE0(sync)` yields `sync`.
pub(crate) fn syscall_define_name(call: Node, source: &[u8]) -> Option<String> {
    if call.kind() != "call_expression" {
        return None;
    }
    let function = call.child_by_field_name("function")?;
    if function.kind() != "identifier" {
        return None;
    }
    if !is_syscall_define_macro(function.utf8_text(source).ok()?) {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let name_node = arguments.named_children(&mut cursor).next()?;
    if name_node.kind() != "identifier" {
        return None;
    }
    Some(name_node.utf8_text(source).ok()?.to_string())
}

/// Given the `SYSCALL_DEFINE` `call_expression`, return the `{ body }` that follows
/// it — the sibling `compound_statement` after the enclosing statement. Absent for a
/// bare macro use with no body, so callers only synthesise for real definitions.
pub(crate) fn syscall_body_of(call: Node) -> Option<Node> {
    // The call is wrapped in an expression_statement (with a recovery-inserted `;`);
    // the body is that statement's next named sibling.
    let statement = call.parent()?;
    let body = statement.next_named_sibling()?;
    (body.kind() == "compound_statement").then_some(body)
}

/// Given a `compound_statement`, return the syscall name if it is the body of a
/// `SYSCALL_DEFINE` — i.e. its preceding sibling is such a call. Mirror of
/// [`syscall_body_of`] for a walk that reaches the body before the signature.
pub(crate) fn syscall_name_for_body(body: Node, source: &[u8]) -> Option<String> {
    if body.kind() != "compound_statement" {
        return None;
    }
    let statement = body.prev_named_sibling()?;
    // The signature is an expression_statement wrapping the call; on some recovery
    // paths the call_expression may be the sibling directly.
    let call = if statement.kind() == "call_expression" {
        statement
    } else {
        let mut cursor = statement.walk();
        let call = statement
            .children(&mut cursor)
            .find(|child| child.kind() == "call_expression");
        call?
    };
    syscall_define_name(call, source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::LanguageParser;
    use std::path::Path;

    fn first_call_expression<'a>(node: Node<'a>) -> Option<Node<'a>> {
        if node.kind() == "call_expression" {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(found) = first_call_expression(child) {
                return Some(found);
            }
        }
        None
    }

    #[test]
    fn recognises_syscall_define_macros() {
        assert!(is_syscall_define_macro("SYSCALL_DEFINE0"));
        assert!(is_syscall_define_macro("SYSCALL_DEFINE6"));
        assert!(is_syscall_define_macro("COMPAT_SYSCALL_DEFINE3"));
        assert!(!is_syscall_define_macro("SYSCALL_DEFINE")); // no arity digit
        assert!(!is_syscall_define_macro("SYSCALL_DEFINE12")); // two digits
        assert!(!is_syscall_define_macro("MY_SYSCALL_DEFINE3"));
        assert!(!is_syscall_define_macro("printf"));
    }

    #[test]
    fn extracts_name_and_body() {
        let code = r#"
SYSCALL_DEFINE3(io_uring_enter, unsigned int, fd, u32, to_submit, u32, flags)
{
	return 0;
}
"#;
        let parser = LanguageParser::new().unwrap();
        let tree = parser.parse_to_tree(Path::new("t.c"), code).unwrap();
        let call = first_call_expression(tree.root_node()).expect("call_expression present");

        assert_eq!(
            syscall_define_name(call, code.as_bytes()).as_deref(),
            Some("io_uring_enter")
        );
        let body = syscall_body_of(call).expect("body present");
        assert_eq!(body.kind(), "compound_statement");
        assert_eq!(
            syscall_name_for_body(body, code.as_bytes()).as_deref(),
            Some("io_uring_enter")
        );
    }

    #[test]
    fn ignores_plain_call_without_body() {
        // A bare macro use with no following body must not be taken as a definition.
        let code = "int x = SYSCALL_DEFINE3(a, b, c);\n";
        let parser = LanguageParser::new().unwrap();
        let tree = parser.parse_to_tree(Path::new("t.c"), code).unwrap();
        let call = first_call_expression(tree.root_node()).expect("call_expression present");

        assert_eq!(
            syscall_define_name(call, code.as_bytes()).as_deref(),
            Some("a")
        );
        assert!(syscall_body_of(call).is_none());
    }
}
