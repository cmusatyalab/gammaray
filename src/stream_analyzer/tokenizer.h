#ifndef __STREAM_ANALYZER_TOKENIZER
#define __STREAM_ANALYZER_TOKENIZER

#include <stddef.h>
#include <stdint.h>

char* tokenize_line(char* stream, int64_t len);
int tokenize_space_split(char* stream,  char* tokens[], int limit, int len);
int tokenize_space_unsplit(char* stream, int len);

#endif
