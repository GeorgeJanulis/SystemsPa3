// add any other includes in the detetc_dups.h file
#include "detect_dups.h"
#include <openssl/md5.h>
#include "uthash.h"
#include <ftw.h>
#include <unistd.h>  // For readlink and realpath
#include <libgen.h>


// define any other global variable you may need over here
typedef struct path_node {
    char *path;
    struct path_node *next;
    ino_t inode;
} path_node;

typedef struct inode_group {
    ino_t inode;
    int count;
    path_node *paths;
    path_node *symlinks;
    struct inode_group *next;
} inode_group;

typedef struct file_entry {
    char md5[33];
    inode_group *inodes;
    path_node *symlinks;
    UT_hash_handle hh;
} file_entry;

file_entry *file_map = NULL;
// open ssl, this will be used to get the hash of the file
EVP_MD_CTX *mdctx;
const EVP_MD *EVP_md5(); // use md5 hash!!

//FileHash *file_hashes = NULL;

void compute_md5(const char *filename, char *output)
{
    const EVP_MD *md = EVP_md5();
    unsigned char buffer[1024];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    size_t bytes;
    FILE *file = fopen(filename, "rb");

    if (!file)
    {
        //printf("symlink?\n");
        output[0] = '0';
        //perror("malloc");
        return;
    }


    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);

    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        EVP_DigestUpdate(mdctx, buffer, bytes);
    }

    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    fclose(file);

    for (unsigned int i = 0; i < hash_len; ++i)
    {
        sprintf(&output[i * 2], "%02x", hash[i]);
    }

    output[32] = '\0';

}

void print_dedup_report() {
    file_entry *entry, *tmp;
    int file_number = 1;

    HASH_ITER(hh, file_map, entry, tmp) {
        printf("File %d\n", file_number++);
        printf("\tMD5 Hash: %s\n", entry->md5);

        inode_group *group = entry->inodes;
        int hardlink_set_number = 1;

        while (group) {
            int softcount = 1;
            printf("\tHard Link (%d): %lu\n", group->count, group->inode);
            path_node *p = group->paths;
            int tf = 0;
            while (p) {
                printf(tf == 0 ? "\t\tPaths:\t%s\n" : "\t\t\t%s\n", p->path);
                tf = 1;
                p = p->next;
            }

            if (group->symlinks) {
                int count = 0;
                path_node *temp = group->symlinks;
                while (temp) {
                    count++;
                    temp = temp->next;
                }

                printf("\t\tSoft Link %d(%d): %lu\n", softcount++, count, group->symlinks->inode);
                temp = group->symlinks;
                tf = 0;
                while (temp) {
                    printf(tf == 0 ? "\t\t\tPaths:\t%s\n" : "\t\t\t%s\n", temp->path);
                    tf = 1;
                    temp = temp->next;
                }
            }

            group = group->next;
            hardlink_set_number++;
        }
    }
}

int main(int argc, char *argv[]) {
    // perform error handling, "exit" with failure incase an error occurs
    //printf("%s\n", argv[1]);
    int r = nftw(argv[1], render_file_info, 10, FTW_PHYS);

    print_dedup_report();

    //print_md5(file_hash->md5);
    //printf("hello");

    // initialize the other global variables you have, if any

    // add the nftw handler to explore the directory
    // nftw should invoke the render_file_info function
}
void is_duplicate(const char *md5, const char *path, const struct stat *sb)
{
    file_entry *entry = NULL;
    HASH_FIND_STR(file_map, md5, entry);

    if (!entry) {
        // New MD5
        entry = calloc(1, sizeof(file_entry));
        strncpy(entry->md5, md5, sizeof(entry->md5));

        inode_group *group = calloc(1, sizeof(inode_group));
        group->inode = sb->st_ino;
        group->count = 1;
        group->paths = NULL;

        path_node *node = malloc(sizeof(path_node));
        node->path = strdup(path);
        node->next = NULL;
        group->paths = node;

        entry->inodes = group;

        HASH_ADD_STR(file_map, md5, entry);
    } else {
        inode_group *group = entry->inodes;
        while (group) {
            if (group->inode == sb->st_ino) {
                // Existing hard link group
                group->count++;
                path_node *node = malloc(sizeof(path_node));
                node->path = strdup(path);
                node->next = group->paths;
                group->paths = node;
                return;
            }
            group = group->next;
        }

        // New hardlink group with same content (different inode)
        inode_group *new_group = calloc(1, sizeof(inode_group));
        new_group->inode = sb->st_ino;
        new_group->count = 1;

        path_node *node = malloc(sizeof(path_node));
        node->path = strdup(path);
        node->next = NULL;
        new_group->paths = node;

        new_group->next = entry->inodes;
        entry->inodes = new_group;
    }
}
void add_symlink(const char *md5, const char *symlink_path) {
    struct stat sb;
    struct stat sb2;
    //printf("hello\n");
    if (lstat(symlink_path, &sb) != 0 || stat(symlink_path, &sb2) != 0)
    {
        perror("stat (symlink)");
        return;
    }

    //printf("hello2\n");
    file_entry *entry;
    HASH_FIND_STR(file_map, md5, entry);
    if (!entry) return;

    inode_group *group = entry->inodes;
    while (group) {
        if (group->inode == sb2.st_ino)
        {
            path_node *new_symlink = malloc(sizeof(path_node));
            new_symlink->path = strdup(symlink_path);
            new_symlink->next = group->symlinks;
            new_symlink->inode = sb.st_ino;
            group->symlinks = new_symlink;
            return;
        }

        group = group->next;
    }
}

// render the file information invoked by nftw
static int render_file_info(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf) {
    // perform the inode operations over here
    //printf("%s\n", fpath);

    if (tflag == FTW_F)
    {
        char md5[33];
        compute_md5(fpath, md5);

        if (md5[0] != '\0')
        {
            is_duplicate(md5, fpath, sb);
        }
    }

    else if (tflag == FTW_SL) {


    // Debugging: Print the symlink target
        //printf("Symlink target: %s\n", fpath);
        char target[PATH_MAX];
        ssize_t len = readlink(fpath, target, sizeof(target) - 1);
        if (len != -1) {
            target[len] = '\0';  // Null-terminate it
            //printf("Symlink points to: %s\n", target);
        } else {
            perror("readlink");
        }
        // Optionally resolve full path
        char resolved_path[PATH_MAX];
        realpath(fpath, resolved_path);
        /*ssize_t len = readlink(fpath, resolved_path, sizeof(resolved_path) - 1);
        resolved_path[len] = '\0';*/
        //printf("hello\n");
        char md5[33];
        compute_md5(resolved_path, md5);

        //printf("%s\n", resolved_path);
        if (md5[0] != '\0') {
            add_symlink(md5, fpath);
        }
    }
    
    

    return 0;

    // invoke any function that you may need to render the file information
}

