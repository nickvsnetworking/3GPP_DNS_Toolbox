#ifndef NAPTR_H
#define NAPTR_H

#include <arpa/nameser.h>

enum { MAX_REGEX_PATTERN_STR = 64,
       MAX_REGEX_REPLACE_STR = 64,
       MAX_SERVICE_STR = 128,
       MAX_REPLACEMENT_STR = 128 };

typedef struct naptr_resource_record {
    struct naptr_resource_record* prev;
    struct naptr_resource_record* next;

    int og_val;
    int order;
    int preference;
    char flag;
    char service[MAX_SERVICE_STR];
    char regex_pattern[MAX_REGEX_PATTERN_STR];
    char regex_replace[MAX_REGEX_REPLACE_STR];
    char replacement[MAX_REPLACEMENT_STR];
} naptr_resource_record;

naptr_resource_record * naptr_query(const char* dname);

naptr_resource_record * naptr_sort(naptr_resource_record **head);

naptr_resource_record * naptr_list_head(naptr_resource_record * nrr);

naptr_resource_record * naptr_remove_resource_record(naptr_resource_record * nrr);

void naptr_free_resource_record_list(naptr_resource_record * nrr);

int naptr_resource_record_list_count(naptr_resource_record * nrr);

#endif /* NAPTR_H */