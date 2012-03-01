#include "tokenizer.h"

char* tokenize_line(char* stream, int64_t len)
{
    int position;
    
    for (position = 0; position < len; position++)
    {
        if (stream[position] == '\n')
        {
            stream[position] = '\0';
            return stream;
        }
    }
    return NULL;
}

int tokenize_space_split(char* stream,  char* tokens[], int limit, int len)
{
    int token, position = 0, notfound;
    for (token = 0; token < limit && position < len; token++)
    {
        tokens[token] = &stream[position];
        notfound = 0;
        for (position = 0; position < len; position++)
        {
            if (stream[position] == ' ')
            {
                stream[position] = '\0';
                position++;
                notfound = 0;
                break;
            }
        }         
        if (notfound)
            tokens[token] = NULL;
    }
    return 0;
}

int tokenize_space_unsplit(char* stream, int len)
{
    int position;

    for (position = 0; position < len; position++)
    {
        if (stream[position] == '\0')
            stream[position] = ' ';
    }
    
    return 0;
}
