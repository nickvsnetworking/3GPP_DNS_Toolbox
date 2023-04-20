#include <ctype.h>
#include <string.h>
#include "regex_extensions.h"


enum { SR_RE_MAX_MATCH = 6 };


static int replace(regmatch_t* pmatch, char* string, char* replacement, char* buf, size_t buf_sz);
static int get_reg_match(char const *pattern, char const *string, regmatch_t *pmatch);

bool reg_match(char const *pattern, char const *string) {
	bool has_match = false;
	regmatch_t pmatch[SR_RE_MAX_MATCH];

	if (0 == get_reg_match(pattern, string, &(pmatch[0]))) {
		has_match = true;
	}

	return has_match;
}

int reg_replace(char *pattern, char *replacement, char *string, char *buf, size_t buf_sz)
{
	regmatch_t pmatch[SR_RE_MAX_MATCH];

    if ((NULL == pattern)     ||
        (NULL == replacement) ||
        (NULL == string)      ||
        (NULL == buf)) {
        return 0;
    }

	if (get_reg_match(pattern, string, &(pmatch[0]))) {
		return -1;
	}

	return replace(&pmatch[0], string, replacement, buf, buf_sz);
}

/*! \brief Replace in replacement tokens \\d with substrings of string pointed by
 * pmatch.
 */
static int replace(regmatch_t* pmatch, char* string, char* replacement, char* buf, size_t buf_sz)
{
	int len;
    int i;
    int j;
    int digit;
    int size;

    if ((NULL == pmatch)      ||
        (NULL == string)      ||
        (NULL == replacement) ||
        (NULL == buf)) {
        return 0;
    }

	len = strlen(replacement);
	j = 0;

	for (i = 0; i < len; i++) {
		if (replacement[i] == '\\') {
			if (i < len - 1) {
				if (isdigit((unsigned char)replacement[i+1])) {
					digit = replacement[i+1] - '0';
					if (pmatch[digit].rm_so != -1) {
						size = pmatch[digit].rm_eo - pmatch[digit].rm_so;
						if (j + size < buf_sz) {
							memcpy(&(buf[j]), string+pmatch[digit].rm_so, size);
							j = j + size;
						} else {
							return -1;
						}
					} else {
						return -2;
					}
					i = i + 1;
					continue;
				} else {
					i = i + 1;
				}
			} else {
				return -3;
			}
		}

		if (j + 1 < buf_sz) {
			buf[j] = replacement[i];
			j = j + 1;
		} else {
			return -4;
		}
	}

	return 1;
}

static int get_reg_match(char const *pattern, char const *string, regmatch_t *pmatch)
{
	regex_t preg;

	if (regcomp(&preg, pattern, REG_EXTENDED | REG_NEWLINE)) {
		return -1;
	}
	if (preg.re_nsub > SR_RE_MAX_MATCH) {
		regfree(&preg);
		return -2;
	}
	if (regexec(&preg, string, SR_RE_MAX_MATCH, pmatch, 0)) {
		regfree(&preg);
		return -3;
	}
	regfree(&preg);
	return 0;
}
