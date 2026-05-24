/*
 * End-to-end fixture for the CWE-680 integer-overflow-to-buffer rules.
 *
 * CWE-680 detection in this analyser is PARTIAL by design — see
 * the rule messages on CWE-680-001 and CWE-680-002. This fixture
 * covers the shapes the rules do model. Bugs hidden behind helpers,
 * value-range bounds checks, or non-literal arithmetic in patterns
 * other than `var * sizeof(T)` are intentionally NOT here.
 *
 * Every function is labelled WRAP (must fire CWE-680-001), SIZEOF
 * (must fire CWE-680-002), or CLEAN (must not fire either).
 */

void *malloc(unsigned long);
void *calloc(unsigned long, unsigned long);
void *realloc(void *, unsigned long);

struct record {
    int field;
};

/* WRAP: 0xFFFF...F * 2 wraps u64 — literal only, fully provable. */
void wrap_malloc_literal_mul(void)
{
    void *p = malloc(0xFFFFFFFFFFFFFFFF * 2);
    (void)p;
}

/* WRAP: 0xFFFF...F + 1 wraps u64. */
void wrap_malloc_literal_add(void)
{
    void *p = malloc(0xFFFFFFFFFFFFFFFF + 1);
    (void)p;
}

/* WRAP: calloc(huge, 2) — implicit multiplication wraps. */
void wrap_calloc_literal(void)
{
    void *p = calloc(0xFFFFFFFFFFFFFFFF, 2);
    (void)p;
}

/* SIZEOF: classic `n * sizeof(T)` shape. */
void sizeof_malloc_n_times_sizeof_struct(unsigned long n)
{
    void *p = malloc(n * sizeof(struct record));
    (void)p;
}

/* SIZEOF: sizeof on the left side. */
void sizeof_malloc_sizeof_times_n(unsigned long n)
{
    void *p = malloc(sizeof(int) * n);
    (void)p;
}

/* SIZEOF: calloc with a variable count. */
void sizeof_calloc_variable_count(unsigned long n)
{
    void *p = calloc(n, sizeof(struct record));
    (void)p;
}

/* CLEAN: both operands literal and well within u64. */
void clean_malloc_constant_mul(void)
{
    void *p = malloc(4 * sizeof(int));
    (void)p;
}

/* CLEAN: calloc with two constants. */
void clean_calloc_two_constants(void)
{
    void *p = calloc(8, sizeof(int));
    (void)p;
}

/* CLEAN: arithmetic without sizeof — out of scope for CWE-680-002,
 *   and literals don't wrap so CWE-680-001 stays quiet too. */
void clean_malloc_variable_no_sizeof(unsigned long n)
{
    void *p = malloc(n * 4);
    (void)p;
}
