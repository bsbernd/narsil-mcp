/*
 * End-to-end fixture for the CWE-122 heap-overflow rule.
 *
 * Every function in this file is one synthetic shape the rule must
 * judge. Comments mark each one OVERFLOW (must fire) or CLEAN (must
 * not fire). The integration test asserts both counts and the
 * function each finding lands in.
 */

/* Prototype-only shims for libc — the rule keys on the call name, not
 * on linking. */
char *malloc(unsigned long);
void *calloc(unsigned long, unsigned long);
char *strdup(const char *);
char *strndup(const char *, unsigned long);
int asprintf(char **, const char *, ...);
int sprintf(char *, const char *, ...);
char *strcpy(char *, const char *);
char *strncpy(char *, const char *, unsigned long);
char *strcat(char *, const char *);
void *memcpy(void *, const void *, unsigned long);
void *memset(void *, int, unsigned long);
unsigned long strlen(const char *);

/* OVERFLOW: 8-byte buffer, 18-byte write. */
void overflow_malloc_strcpy(void)
{
    char *dst = malloc(8);
    strcpy(dst, "very long literal");
}

/* CLEAN: exact-fit allocation. */
void clean_malloc_strcpy(const char *name)
{
    char *dst = malloc(strlen(name) + 1);
    strcpy(dst, name);
}

/* OVERFLOW: asprintf gives strlen(name) + 1; sprintf writes
 *   strlen(prefix) + 1 + strlen(name) + 1 NUL. */
void overflow_asprintf_then_sprintf(const char *prefix, const char *name)
{
    char *dst;
    asprintf(&dst, "%s", name);
    sprintf(dst, "%s#%s", prefix, name);
}

/* OVERFLOW: calloc gives 32, memset writes 40. */
void overflow_calloc_memset(void)
{
    char *dst = calloc(4, 8);
    memset(dst, 0, 40);
}

/* CLEAN: memcpy size matches the allocation. */
void clean_calloc_memcpy(const char *src)
{
    char *dst = calloc(1, 16);
    memcpy(dst, src, 16);
}

/* OVERFLOW: strdup gives strlen(name) + 1; sprintf writes twice
 *   strlen(name) plus separator and NUL. */
void overflow_strdup_then_sprintf(const char *name)
{
    char *dst = strdup(name);
    sprintf(dst, "%s#%s", name, name);
}

/* CLEAN: strndup gives 17 (16 + NUL); strcpy writes 14 (13 + NUL). */
void clean_strndup_then_strcpy(const char *name)
{
    char *dst = strndup(name, 16);
    strcpy(dst, "thirteen0000");
}

/* OVERFLOW via cross-function helper. */
char *helper(const char *name)
{
    return malloc(strlen(name));
}

void overflow_through_helper(const char *user_input)
{
    char *dst = helper(user_input);
    /* strcpy writes strlen(user_input) + 1; helper returned
     * strlen(user_input). The constant differs in the right
     * direction → provable overflow. */
    strcpy(dst, user_input);
}
