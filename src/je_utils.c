#include <stdbool.h>

#include <jemalloc/jemalloc.h>

#include <rte_memcpy.h>

char* je_strdup(const char* s) {
    size_t len = strlen(s) + 1;
    char*  new = je_malloc(len);
    if (new == NULL)
        return NULL;
    return (char*) rte_memcpy(new, s, len);
}

char* je_strndup(const char* s, size_t n) {
    size_t len = strnlen(s, n);
    char*  new = je_malloc(len + 1);
    if (new == NULL)
        return NULL;
    new[len] = '\0';
    return (char *) rte_memcpy(new, s, len);
}
