#include <ctype.h>
#include <string.h>
#include "regex_extensions.h"


enum { SR_RE_MAX_MATCH = 6 };


static int replace(regmatch_t* pmatch, char* string, char* replacement, char* buf, size_t buf_sz);


int reg_match(char *pattern, char *string, regmatch_t *pmatch)
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

int reg_replace(char *pattern, char *replacement, char *string, char *buf, size_t buf_sz)
{
	regmatch_t pmatch[SR_RE_MAX_MATCH];

	if (reg_match(pattern, string, &(pmatch[0]))) {
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
    int size;;

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
