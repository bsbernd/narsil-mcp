//! Response size budget: keep one tool result small enough to be worth reading.
//!
//! List-shaped tools cap their own output and print a footer naming the exact
//! follow-up call; `clamp` is the last-resort backstop for everything else.

use std::collections::HashMap;

/// Items rendered when the caller passes no `limit`. Sized so a capped list
/// costs a few thousand tokens at the 60-160 bytes per line these renderers
/// emit.
pub const DEFAULT_LIST_LIMIT: usize = 50;

/// Hard ceiling on one tool response. Above this the MCP layer cuts on a line
/// boundary: a truncated answer beats an unusable session.
pub const MAX_RESPONSE_BYTES: usize = 48 * 1024;

/// The caller's window into a list-shaped result. One value rather than a pair
/// of `usize` arguments: the tools that take it already carry enough of those.
#[derive(Clone, Copy, Debug)]
pub struct ListWindow {
    /// Index of the first item to render.
    pub offset: usize,
    /// Items to render; 0 means no cap.
    pub limit: usize,
}

impl ListWindow {
    pub fn new(offset: usize, limit: usize) -> Self {
        Self { offset, limit }
    }
}

/// What a list render dropped, and how to ask for the rest.
pub struct ListCap {
    /// Tool name, used to spell the follow-up call in the footer.
    pub tool: &'static str,
    /// Items the query matched, before the cap.
    pub total: usize,
    /// Items actually rendered.
    pub shown: usize,
    /// Index of the first item rendered (the caller's `offset`).
    pub offset: usize,
}

impl ListCap {
    /// Empty when nothing was dropped; otherwise one line naming the next page
    /// and the way to get everything.
    pub fn footer(&self) -> String {
        if self.shown >= self.total.saturating_sub(self.offset) {
            return String::new();
        }
        format!(
            "*Showing {} of {}. Next page: {}(offset={}). All: {}(limit=0).*\n",
            self.shown,
            self.total,
            self.tool,
            self.offset + self.shown,
            self.tool
        )
    }

    /// True when items were dropped from the end of the caller's window.
    pub fn truncated(&self) -> bool {
        self.offset + self.shown < self.total
    }
}

/// Slice `items` to the caller's window and describe what was dropped.
///
/// `window.limit == 0` means "no cap" — the escape hatch for a caller that
/// really wants all of it.
pub fn cap<'a, T>(items: &'a [T], window: ListWindow, tool: &'static str) -> (&'a [T], ListCap) {
    let total = items.len();
    let offset = window.offset.min(total);
    let end = if window.limit == 0 {
        total
    } else {
        (offset + window.limit).min(total)
    };
    let page = &items[offset..end];
    (
        page,
        ListCap {
            tool,
            total,
            shown: page.len(),
            offset,
        },
    )
}

/// Group dropped items by file so the shape of the remainder survives the cut.
///
/// Rows are sorted by count descending (ties broken by path for a stable
/// render) and themselves capped at `max_rows`.
pub fn by_file_summary<T>(dropped: &[T], file_of: impl Fn(&T) -> &str, max_rows: usize) -> String {
    if dropped.is_empty() {
        return String::new();
    }

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for item in dropped {
        *counts.entry(file_of(item)).or_insert(0) += 1;
    }

    let mut rows: Vec<(&str, usize)> = counts.into_iter().collect();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));

    let shown_rows = if max_rows == 0 {
        rows.len()
    } else {
        max_rows.min(rows.len())
    };

    let mut output = String::new();
    for (file, count) in &rows[..shown_rows] {
        output.push_str(&format!("- `{}` — {}\n", file, count));
    }
    if shown_rows < rows.len() {
        output.push_str(&format!(
            "- *(+ {} further files)*\n",
            rows.len() - shown_rows
        ));
    }
    output
}

/// Backstop for output that was rendered without a cap.
///
/// Cuts on the last line boundary under [`MAX_RESPONSE_BYTES`] and appends a
/// notice naming `tool`. Returns `text` untouched when already under budget.
pub fn clamp(text: String, tool: &str) -> String {
    if text.len() <= MAX_RESPONSE_BYTES {
        return text;
    }

    // Cut at the last newline inside the budget so the response never ends
    // mid-line; fall back to a char boundary when a single line exceeds it.
    let cut = match text[..MAX_RESPONSE_BYTES].rfind('\n') {
        Some(nl) => nl + 1,
        None => {
            let mut boundary = MAX_RESPONSE_BYTES;
            while boundary > 0 && !text.is_char_boundary(boundary) {
                boundary -= 1;
            }
            boundary
        }
    };

    let dropped = text.len() - cut;
    let mut clamped = text;
    clamped.truncate(cut);
    clamped.push_str(&format!(
        "\n*Response truncated: {} of {} bytes dropped. `{}` returned more \
         than the {} KB budget — narrow the query (path, pattern, limit).*\n",
        dropped,
        dropped + cut,
        tool,
        MAX_RESPONSE_BYTES / 1024
    ));
    clamped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_windows_and_reports_total() {
        let items: Vec<usize> = (0..553).collect();
        let (page, capped) = cap(
            &items,
            ListWindow::new(0, DEFAULT_LIST_LIMIT),
            "get_callers",
        );
        assert_eq!(page.len(), 50);
        assert_eq!(page[0], 0);
        assert_eq!(capped.total, 553);
        assert!(capped.truncated());
    }

    #[test]
    fn cap_offset_pages_forward() {
        let items: Vec<usize> = (0..553).collect();
        let (page, capped) = cap(&items, ListWindow::new(50, 50), "get_callers");
        assert_eq!(page[0], 50);
        assert_eq!(capped.offset, 50);
        assert!(capped.footer().contains("offset=100"));
    }

    #[test]
    fn cap_limit_zero_returns_everything() {
        let items: Vec<usize> = (0..553).collect();
        let (page, capped) = cap(&items, ListWindow::new(0, 0), "get_callers");
        assert_eq!(page.len(), 553);
        assert!(!capped.truncated());
        assert!(capped.footer().is_empty());
    }

    #[test]
    fn cap_offset_past_end_is_empty_not_panic() {
        let items: Vec<usize> = (0..10).collect();
        let (page, capped) = cap(&items, ListWindow::new(99, 50), "get_callers");
        assert!(page.is_empty());
        assert_eq!(capped.offset, 10);
    }

    /// A capped list that reads as complete is worse than a long one, so the
    /// footer must always carry the total and the escape hatch.
    #[test]
    fn footer_names_total_and_escape_hatch() {
        let items: Vec<usize> = (0..553).collect();
        let (_, capped) = cap(&items, ListWindow::new(0, 50), "get_callers");
        let footer = capped.footer();
        assert!(footer.contains("50 of 553"));
        assert!(footer.contains("get_callers(offset=50)"));
        assert!(footer.contains("get_callers(limit=0)"));
    }

    #[test]
    fn by_file_summary_ranks_and_caps_rows() {
        let dropped = vec!["a.c", "a.c", "a.c", "b.c", "b.c", "c.c", "d.c"];
        let summary = by_file_summary(&dropped, |path| path, 2);
        assert!(summary.starts_with("- `a.c` — 3\n"));
        assert!(summary.contains("- `b.c` — 2\n"));
        assert!(summary.contains("(+ 2 further files)"));
    }

    #[test]
    fn clamp_leaves_small_responses_alone() {
        let text = "short\n".to_string();
        assert_eq!(clamp(text.clone(), "get_file"), text);
    }

    #[test]
    fn clamp_cuts_on_a_line_boundary() {
        let text = "0123456789\n".repeat(MAX_RESPONSE_BYTES / 4);
        let clamped = clamp(text, "get_contributors");
        assert!(clamped.len() < MAX_RESPONSE_BYTES + 512);
        assert!(clamped.contains("Response truncated"));
        assert!(clamped.contains("get_contributors"));
        let body = clamped.split("\n*Response truncated").next().unwrap();
        assert!(body.trim_end().ends_with("0123456789"));
    }

    #[test]
    fn clamp_handles_one_huge_line() {
        let text = "x".repeat(MAX_RESPONSE_BYTES * 2);
        let clamped = clamp(text, "get_file");
        assert!(clamped.contains("Response truncated"));
    }
}
