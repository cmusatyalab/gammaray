/*****************************************************************************
 * bson.h                                                                    *
 *                                                                           *
 * This file contains prototypes for functions implementing a BSON encoder   *
 * and decoder library in C.                                                 *
 *                                                                           *
 *                                                                           *
 *   Authors: Wolfgang Richter <wolf@cs.cmu.edu>                             *
 *                                                                           *
 *                                                                           *
 *   Copyright 2013-2014 Carnegie Mellon University                          *
 *                                                                           *
 *   Licensed under the Apache License, Version 2.0 (the "License");         *
 *   you may not use this file except in compliance with the License.        *
 *   You may obtain a copy of the License at                                 *
 *                                                                           *
 *       http://www.apache.org/licenses/LICENSE-2.0                          *
 *                                                                           *
 *   Unless required by applicable law or agreed to in writing, software     *
 *   distributed under the License is distributed on an "AS IS" BASIS,       *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.*
 *   See the License for the specific language governing permissions and     *
 *   limitations under the License.                                          *
 *****************************************************************************/
#ifndef __GAMMARAY_BSON_H
#define __GAMMARAY_BSON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <stdio.h>

/* lib constants */
enum BSON_TYPE
{
    BSON_DOUBLE = 0x01,
    BSON_STRING = 0x02,
    BSON_EMBEDDED_DOCUMENT = 0x03,
    BSON_ARRAY = 0x04,
    BSON_BINARY = 0x05,
    BSON_UNDEFINED = 0x06,          /* DEPRECATED */
    BSON_OBJECTID = 0x07,           /* 12 bytes */
    BSON_BOOLEAN = 0x08,
    BSON_UTC_DATETIME = 0x09,
    BSON_NULL = 0x0a,
    BSON_REGEX = 0x0b,
    BSON_DBPOINTER = 0x0c,
    BSON_JS = 0x0d,                 /* JS code */
    BSON_SYMBOL = 0x0e,             /* symbol */
    BSON_JS_CODE = 0x0f,            /* includes scope */
    BSON_INT32 = 0x10,              /* 32 bit signed */
    BSON_TIMESTAMP = 0x11,          /* MongoDB-specific timestamp */
    BSON_INT64 = 0x12,              /* 64 bit signed */
    BSON_MIN = 0xff,                /* minimum key by comparison */
    BSON_MAX = 0x7f                 /* maximum key by comparison */
};

enum BSON_SUBTYPE
{
    BSON_BINARY_GENERIC = 0x00,
    BSON_FUNCTION = 0x01,
    BSON_BINARY_OLD = 0x02,
    BSON_UUID = 0x03,
    BSON_MD5 = 0x05,
    BSON_USER = 0x80
};
  
/* lib structs */
struct bson_info;

struct bson_kv
{
    enum BSON_TYPE type;
    enum BSON_SUBTYPE subtype;
    int32_t size;
    const char* key;
    const void* data;
};

/**
 * bson_init
 *
 * initializes the bson_info datastructure which keps information for the
 * rest of the library to reference.
 *
 * @param bson_info - used in all calls into the library, gets setup here
 * @return - EXIT_FAILURE if malloc fails, otherwise EXIT_SUCCESS
 *
 */
struct bson_info*
bson_init();

/**
 * bson_serialize
 *
 * serializes an object as specified in the BSON spec into a buffer.
 *
 * @param bson_info - keeps references to buffer and other metadata
 * @param key - this is the C-string (nul terminated) key as used in BSON
 * @param value - this is the type-specified value to be BSON encoded
 * @return - EXIT_SUCCESS on success, EXIT_FAILURE if anything bad happens
 *
 */
int
bson_serialize(struct bson_info* bson_info, struct bson_kv* value);

/**
 * bson_finalize
 *
 * performs framing around the BSON encoded data in the buffer in bson_info
 * 
 * Note: You can not serialize more objects into the buffer after this point,
 *       otherwise bad things will happen (not guarded against currently).
 *
 * @param bson_info - metadata structure with buffer to be finalized
 * @return EXIT_SUCCESS if finalizig succeeds, EXIT_FAILURE otherwise
 *
 */
int
bson_finalize(struct bson_info* bson_info);

/**
 * bson_write
 *
 * Helper function to write the BSON-encoded buffer into a file descriptor. 
 *
 * @param bson_info - metadata structure containing buffer to be written
 * @param file - file with write permissions and opened for writing
 * @return EXIT_SUCCESS on success, EXIT_FAILURE otherwise
 *
 */
int
bson_writef(struct bson_info* bson_info, int fd);

/**
 * bson_cleanup
 *
 * this function should be called before exit, it frees the buffer and performs
 * cleanup of the metadata structure (no longer usable after this)
 *
 * @param bson_info - the metadata structure to be cleaned up
 *
 */
void
bson_cleanup(struct bson_info* bson_info);

/**
 * bson_reset
 *
 * This function resets a bson_info datastructure to contain nothing.
 *
 * @param bson_info - the metadata structure to reset
 *
 */
void
bson_reset(struct bson_info* bson_info);

/**
 * bson_read
 *
 * This function reads an entire file into memory and stores it into a buffer
 * maintained by the bson_info metadata structure.
 *
 * @param bson_info - the metadata structure to read into
 * @param fname - the file name to read from on disk
 * @return EXIT_SUCCESS on success, EXIT_FAILURE otherwise
 *
 */
int
bson_read(struct bson_info* bson_info, const char* fname);

/**
 * bson_readf
 *
 * This function reads an single BSON document into memory and stores it into a
 * buffer maintained by the bson_info metadata structure.
 *
 * @param bson_info - the metadata structure to read into
 * @param file - the file descriptor to read from on disk
 * @return EXIT_SUCCESS on success, EXIT_FAILURE otherwise
 *
 */
int
bson_readf(struct bson_info* bson_info, int fd);

 /**
  * bson_make_readable
  *
  * This function makes a bson_info struct ready to be deserialized.  Useful
  * for in-memory passing that is not hitting disk (bson_read does the
  * requisite work).
  * 
  *
  * @param bson_info - the metadata structure to read into
  * @param file - the file to read from on disk
  * @return EXIT_SUCCESS on success, EXIT_FAILURE otherwise
  *
  */
int
bson_make_readable(struct bson_info* bson_info);

/**
 * bson_deserialize
 *
 * This function should be called multiple times, it will consume the buffer in
 * the metadata structure bson_info.  It returns one deserialized object at a
 * time, and should be called multiple times until NULL is returned.
 *
 * @param bson_info - the metadata structure to deserialize from
 * @param value - pointer to bson_kv struct to deserialize data into
 * @return 0 when nothing more to process, 1 on success, -1 on failure 
 *
 */
int
bson_deserialize(struct bson_info* bson_info, struct bson_kv* value,
                 struct bson_kv* value2);

/**
 * bson_print
 *
 * This function prints a BSON stream as a set of key-value pairs.
 *
 * @param bson_info - the BSON stream to print
 * @param stream - the stream to print to
 * @return - EXIT_SUCCESS on success, EXIT_FAILURE otherwise
 *
 */
int
bson_print(FILE* stream, struct bson_info* bson);

#ifdef __cplusplus
}
#endif

#endif
