// Do not forget to add the macro FUSE_USE_VERSION
#define FUSE_USE_VERSION 34

// Max 10 files can be stored in the root directory
#define MAX_FILES 10

#define MAX_FILENAME_LEN 64

#include <fuse3/fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>

// Structure for storing information about a file in our filesystem
struct file_info
{
    size_t size; // size of the file
    char *data; // file contents
    char *name; // file name
    mode_t mode; // mode (permissions)
    ino_t ino; // inode number
    bool is_used; // is the current slot used
};

// Structure for handling directory entries
struct dirbuf
{
    char *p;
    size_t size;
};

// Storage for files
struct file_info files[MAX_FILES];

void fatal_error(const char *message)
{
    puts(message);
    exit(1);
}

// A macro for adding a new entry
#define DIRBUF_ADDENTRY(req, b, name, ino)                                                      \
    do                                                                                          \
    {                                                                                           \
        struct stat stbuf;                                                                      \
        size_t oldsize = (b)->size;                                                             \
        (b)->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);                            \
        (b)->p = (char *)realloc((b)->p, (b)->size);                                            \
        memset(&stbuf, 0, sizeof(stbuf));                                                       \
        stbuf.st_ino = ino;                                                                     \
        fuse_add_direntry(req, (b)->p + oldsize, (b)->size - oldsize, name, &stbuf, (b)->size); \
    } while (0)

#define min(x, y) ((x) < (y) ? (x) : (y))

static void init_handler(void *userdata, struct fuse_conn_info *conn)
{
    // Called when libfuse establishes communication with the FUSE kernel module.
    puts("init_handler called");
    for (int i = 0; i < MAX_FILES; i++)
    {
        files[i].data = NULL;
        files[i].mode = 0;
        files[i].size = 0;
        files[i].is_used = false;
        files[i].name = (char *)malloc(MAX_FILENAME_LEN);
        files[i].ino = 2;
    }
}

static void lookup_handler(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    printf("lookup_handler called: looking for %s\n", name);
    struct fuse_entry_param e;

    memset(&e, 0, sizeof(e));

    // Ensure that the parent is the root directory
    if (parent == 1)
    {
        for (int i = 0; i < MAX_FILES; i++)
        {
            // If the file if found
            if (strcmp(files[i].name, name) == 0)
            {
                e.ino = files[i].ino;
                e.attr.st_ino = files[i].ino;
                e.attr.st_mode = files[i].mode;
                e.attr_timeout = 1.0;
                e.entry_timeout = 1.0;
                e.attr.st_nlink = 1;
                e.attr.st_size = files[i].size;
                fuse_reply_entry(req, &e);
                return;
            }
        }
    }
    // No entry found
    fuse_reply_err(req, ENOENT);
}

static void getattr_handler(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    puts("getattr_handler called");
    struct stat stbuf;

    // Is a directory (root directory of our filesystem)
    if (ino == 1)
    {
        stbuf.st_mode = S_IFDIR | 0755;
        stbuf.st_nlink = 2;
        fuse_reply_attr(req,&stbuf,1.0);
        return;
    }
    else
    {
        for(int i=0;i<MAX_FILES;i++){
            // File found, get some attributes such as mode, size and number of hardlinks
            if(files[i].ino == ino){
                stbuf.st_nlink = 1;
                stbuf.st_mode = files[i].mode;
                stbuf.st_size = files[i].size;
                fuse_reply_attr(req,&stbuf,1.0);
                return;
            }
        }

    }

    fuse_reply_err(req,ENOENT);
}


static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
                             off_t off, size_t maxsize)
{
    if (off < bufsize)
        return fuse_reply_buf(req, buf + off,
                              min(bufsize - off, maxsize));
    else
        return fuse_reply_buf(req, NULL, 0);
}

void readdir_handler(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                     struct fuse_file_info *fi)
{
    printf("readdir_handler called with the inode number %ld\n", ino);
    (void)fi;

    // Currently there's only one directory present in our filesystem, the root directory
    if (ino != 1)
        fuse_reply_err(req, ENOTDIR);
    else
    {
        struct dirbuf b;

        memset(&b, 0, sizeof(b));
        // Add entries for . and ..
        DIRBUF_ADDENTRY(req, &b, ".", 1);
        DIRBUF_ADDENTRY(req, &b, "..", 1);

        for (int i = 0; i < MAX_FILES; i++)
        {
            if (files[i].is_used)
            {
                printf("Adding entry for filename -> %s | inode -> %ld\n", files[i].name, files[i].ino);
                DIRBUF_ADDENTRY(req, &b, files[i].name, files[i].ino);
            }
        }

        reply_buf_limited(req, b.p, b.size, off, size);
        free(b.p);
    }
}

void opendir_handler(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    puts("opendir_handler called");
    if (ino != 1)
    {
        // Inode number for the only directory right now is 1
        fuse_reply_err(req, ENOTDIR);
    }
    else
    {
        fuse_reply_open(req, fi);
    }
}

static void open_handler(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    puts("open_handler called");
    if (ino < 2)
    {
        // Inode number 1, i.e a directory
        fuse_reply_err(req, EISDIR);
    }
    else
    {
        // Open the file
        fuse_reply_open(req, fi);
    }
}

static void create_handler(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi)
{
    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));

    printf("create_handler called with the filename as %s and mode as %d\n", name, mode);

    if (parent != 1)
    {
        // The root directory is the parent of all files
        fuse_reply_err(req, ENOENT);
        return;
    }

    for (int i = 0; i < MAX_FILES; i++)
    {
        if (files[i].is_used == false)
        {
            files[i].is_used = true;
            files[i].mode = S_IFREG | mode;
            files[i].size = 0x0;
            files[i].data = NULL;
            files[i].ino = i + 2;
            strncpy(files[i].name, name, strlen(name));
            files[i].name[strlen(name)] = 0x0;

            e.ino = i + 2; // the inode number of the root directory of our filesystem is 1.
            e.attr.st_ino = i + 2;
            e.attr.st_mode = S_IFREG | mode;
            e.attr.st_nlink = 1;
            e.attr.st_size = 0x0;

            fuse_reply_create(req, &e, fi);
            return;
        }
    }
    fuse_reply_err(req, ENOSPC);
}

static void read_handler(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
    printf("read_handler called for the file with inode number %ld\n", ino);
    if (ino < 2)
    {
        fuse_reply_err(req, EISDIR);
    }
    else
    {
        for (int i = 0; i < MAX_FILES; i++)
        {
            if (files[i].ino == ino)
            {
                reply_buf_limited(req, files[i].data, files[i].size, off, size);
                return;
            }
        }
        fuse_reply_err(req, ENOENT);
    }
}

static void write_handler(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
    printf("write_handler called on the file with inode number %ld\n", ino);
    printf("offset = %lu and size=%zu\n", off, size);
    if (ino < 2)
    {
        fuse_reply_err(req, EISDIR);
    }
    else
    {
        for (int i = 0; i < MAX_FILES; i++)
        {
            if (files[i].ino == ino)
            {
                if (files[i].size == 0)
                {
                    files[i].data = malloc(size + off);
                }
                else
                {
                    files[i].data = realloc(files[i].data, off + size);
                }
                files[i].size = off + size;
                memcpy(files[i].data + off, buf, size);
                fuse_reply_write(req, size);
                return;
            }
        }
    }
}


static void setattr_handler(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi)
{
    puts("setattr_handler called");
    struct stat stbuf;

    if (ino < 2)
    {
        fuse_reply_err(req, EISDIR);
        return;
    }
    for (int i = 0; i < MAX_FILES; i++)
    {
        if (files[i].ino == ino)
        {
            stbuf.st_ino = ino;
            stbuf.st_mode = files[i].mode;
            stbuf.st_nlink = 1;
            stbuf.st_size = files[i].size;

            if (to_set & FUSE_SET_ATTR_ATIME)
            {
                stbuf.st_atime = attr->st_atime;
            }
            if (to_set & FUSE_SET_ATTR_MTIME)
            {
                stbuf.st_mtime = attr->st_mtime;
            }
            if (to_set & FUSE_SET_ATTR_CTIME)
            {
                stbuf.st_ctime = attr->st_ctime;
            }
            fuse_reply_attr(req, &stbuf, 1.0);
            return;
        }
    }
}

static struct fuse_lowlevel_ops operations = {
    .lookup = lookup_handler,
    .init = init_handler,
    .open = open_handler,
    .read = read_handler,
    .create = create_handler,
    .write = write_handler,
    .getattr = getattr_handler,
    .setattr = setattr_handler,
    .opendir = opendir_handler,
    .readdir = readdir_handler,
};

int main(int argc, char **argv)
{
    int retval = 0;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_cmdline_opts opts;
    struct fuse_session *se;

    if (fuse_parse_cmdline(&args, &opts))
    {
        return 1;
    }
    if (opts.show_help)
    {
        printf("Usage: %s [options] <mountpoint>\n", argv[0]);
        fuse_cmdline_help();
        return 0;
    }
    if (opts.show_version)
    {
        fuse_lowlevel_version();
        return 0;
    }
    if (opts.mountpoint == NULL)
    {
        printf("Usage: %s [options] <mountpoint>\n", argv[0]);
        return 1;
    }

    se = fuse_session_new(&args, &operations, sizeof(operations), NULL);
    if (se == NULL)
    {
        free(opts.mountpoint);
        fuse_opt_free_args(&args);
        return 1;
    }

    if (fuse_set_signal_handlers(se) != 0)
    {
        retval = 1;
        goto errlabel_two;
    }

    if (fuse_session_mount(se, opts.mountpoint) != 0)
    {
        retval = 1;
        goto errlabel_one;
    }

    fuse_session_loop(se);

    fuse_session_unmount(se);
errlabel_one:
    fuse_remove_signal_handlers(se);

errlabel_two:
    fuse_session_destroy(se);
    free(opts.mountpoint);
    fuse_opt_free_args(&args);
    return retval;
}
