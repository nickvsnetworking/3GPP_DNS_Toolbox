#ifndef REGEX_EXTENSION_H
#define REGEX_EXTENSION_H


#include <regex.h>


/*! \brief Match pattern against string and store result in pmatch */
int reg_match(char *pattern, char *string, regmatch_t *pmatch);


/*! \brief Match pattern against string and, if match succeeds, and replace string
 * with replacement substituting tokens \\d with matched substrings.
 */
int reg_replace(char *pattern, char *replacement, char *string, char *buf, size_t buf_sz);


#endif /* REGEX_EXTENSION_H */