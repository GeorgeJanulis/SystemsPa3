// add any other includes in the detetc_dups.h file
#include "detect_dups.h"
#include <openssl/md5.h>
#include "uthash.h"
#include <ftw.h>
#include <unistd.h>  // For readlink and realpath


// define any other global variable you may need over here
typedef struct path_node {
    char *path;
    struct path_node *next;
} path_node;

typedef struct file_entry {
    char md5[33];
    ino_t inode;
    int hardlink_count;
    path_node *paths;      // hard link paths
    path_node *symlinks;   // symlink paths
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
        printf("File %d:\n", file_number++);
        printf("\tMD5 Hash: %s\n", entry->md5);
        printf("\t\tHard Link (%d): %lu\n", entry->hardlink_count, entry->inode);

        path_node *p = entry->paths;
        while (p) {
            printf("\t\t\tPaths:\t%s\n", p->path);
            p = p->next;
        }

        // Print symlinks if any
        int symlink_count = 0;
        path_node *s = entry->symlinks;
        while (s) {
            if (symlink_count == 0) {
                printf("\t\t\tSoft Link 1: %lu\n", entry->inode);
            }
            printf("\t\t\t\tPaths:\t%s\n", s->path);
            s = s->next;
            symlink_count++;
        }
    }
}


int main(int argc, char *argv[]) {
    // perform error handling, "exit" with failure incase an error occurs

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

    // Check if we've seen this hash before
    HASH_FIND_STR(file_map, md5, entry);

    if (!entry) {
        // First time seeing this hash: create a new entry
        entry = malloc(sizeof(file_entry));
        if (!entry) {
            perror("malloc");
            return;
        }

        strncpy(entry->md5, md5, sizeof(entry->md5));
        entry->inode = sb->st_ino;
        entry->hardlink_count = 1;
        entry->paths = NULL;
        entry->symlinks = NULL;

        path_node *node = malloc(sizeof(path_node));
        node->path = strdup(path);
        node->next = NULL;
        entry->paths = node;

        HASH_ADD_STR(file_map, md5, entry);
    } else {
        // Same hash seen before
        if (entry->inode == sb->st_ino) {
            // Same inode = hard link
            entry->hardlink_count++;

            // Add to paths list
            path_node *node = malloc(sizeof(path_node));
            node->path = strdup(path);
            node->next = entry->paths;
            entry->paths = node;
        } else {
            // Different inode but same content = soft duplicate (not a hard link)
            // We assume one inode per md5, so you can adapt this if needed
            // For now, treat it like a new hard link group under same MD5

            // Could track multiple inodes under one hash if needed
            fprintf(stderr, "Warning: same MD5 but different inode for: %s\n", path);
        }
    }
}
void add_symlink(const char *md5, const char *symlink_path) {
    file_entry *entry;
    HASH_FIND_STR(file_map, md5, entry);
    if (entry) {
        path_node *new_symlink = malloc(sizeof(path_node));
        new_symlink->path = strdup(symlink_path);
        new_symlink->next = entry->symlinks;
        entry->symlinks = new_symlink;
    }
}

// render the file information invoked by nftw
static int render_file_info(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf) {
    // perform the inode operations over here

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
        struct stat target;
        char resolved_path[PATH_MAX];
        char md5[33];
        compute_md5(fpath, md5);
        printf("%s\n", md5);

        //printf("hello");
        add_symlink(md5, fpath);
        

        /*if (stat(fpath, &target) != 0) {
            perror("stat failed for symlink");
            printf("Symlink path: %s\n", fpath);
        } else if (S_ISREG(target.st_mode)) {
            printf("Symlink points to regular file: %s\n", fpath);
            insert_symlink(fpath, target.st_ino, target.st_dev);
        } else {
            printf("Symlink points to something else: %s (mode: %o)\n", fpath, target.st_mode);
        }*/
    }
    

    return 0;

    // invoke any function that you may need to render the file information
}
