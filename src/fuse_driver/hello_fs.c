#define FUSE_USE_VERSION 28

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <fuse.h>

static const char* hello_str  = "Hello World.\n";
static const char* hello_path = "/hello";

static int hellofs_getattr(const char* path, struct stat* stbuf)
{
    int result = 0; /* temporary result */

    memset(stbuf, 0, sizeof(struct stat));

    if (strncmp(path, "/", 1) == 0 && strlen(path) == 1)
    {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    }
    else if (strncmp(path, hello_path, strlen(hello_path)) == 0)
    {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = strlen(hello_str);
    }
    else
    {
        result = -ENOENT;
    }
    return result;
}

static int hellofs_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                           off_t offset, struct fuse_file_info* fi)
{
    if (strncmp(path, "/", 1) != 0)
        return -ENOENT;

   filler(buf, ".", NULL, 0);
   filler(buf, "..", NULL, 0);
   filler(buf, hello_path + 1, NULL, 0);
   return 0; 
}

static int hellofs_open(const char* path, struct fuse_file_info* fi)
{
    if (strncmp(path, hello_path, strlen(hello_path)) != 0)
        return -ENOENT;
    
    if ((fi->flags & 3) != O_RDONLY)
        return -EACCES;

    return 0;
}

static int hellofs_read(const char* path, char* buf, size_t size, off_t offset,
                        struct fuse_file_info* fi)
{
    size_t len;

    if (strncmp(path, hello_path, strlen(hello_path)) != 0)
        return -ENOENT;

    len = strlen(hello_str);

    if (offset < len)
    {
        if (offset + size > len)
            size = len - offset;

        memcpy(buf, hello_str + offset, size);
    }
    else
    {
        size = 0;
    }

    return size;
}

static struct fuse_operations hellofs_oper = {
                                                .getattr = hellofs_getattr,
                                                .readdir = hellofs_readdir,
                                                .open    = hellofs_open,
                                                .read    = hellofs_read
                                             };

int main(int argc, char* argv[])
{
    return fuse_main(argc, argv, &hellofs_oper, NULL);
}
