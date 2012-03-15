#include <stdio.h>
#include <stdlib.h>
#include "../disk_analyzer/color.h"

int init(struct hashtable* ht)
{
   ht->table = malloc(sizeof(struct hashtable) * INIT_SIZE); 
   if (ht->table == NULL)
       return EXIT_FAILURE;
   return EXIT_SUCCESS;
}

uint32_t compute_mask(struct hashtable* ht)
{
    uint64_t current_size = ht->size;
    uint32_t mask = 0, log2 = 0;

    while (current_size > 1)
    {
        current_size = current_size >> 1;
        mask ^= (1 << log2);
        log2++;
    }
    return mask;
}

struct element get(struct hashtable* ht, void* key, int keylen)
{
    if (ht->elements == 0)
        return EXIT_FAILURE;
    uint32_t mask = compute_mask(ht);
    uint32_t current_hash = SuperFastHash(key, keylen) & mask;

    while (ht->elements[current_hash]->equal(key) == 0 &&
           ht->elements[current_hash] != 0)
    {
        current_hash = SuperFastHash((const char*) &current_hash, 4);
    }

    return ht->elements[current_hash];
}

/* double the size, reinsert all elements */
int resize(struct hashtable* ht)
{
}

/* return 0 on safe load
 * return 1 on high load */
int check_load(struct hashtable* ht)
{
    uint64_t current_size = ht->size;
    uint64_t current_elements = ht->elements;

    return (current_size >> 1 )  / current_elements >= 1;
}

int put (struct hashtable* ht, struct element)
{
    uint32_t mask = compute_mask(ht);
    uint32_t current_hash = SuperFastHash(key, keylen) & mask;

    while (ht->elements[current_hash]->equal(key) == 0 &&
           ht->elements[current_hash] != 0)
    {
        current_hash = SuperFastHash((const char*) &current_hash, 4);
    }
    /* need to insert the element, if half full, resize) */
}
