// add any other includes in the detetc_dups.h file
#include "detect_dups.h"
#include <openssl/md5.h>
#include "uthash.h"
#include <ftw.h>
#include <unistd.h>  // For readlink and realpath


// define any other global variable you may need over here

typedef struct FileEntry {
    char *filepath;
    ino_t inode;
    dev_t dev;
    mode_t mode;
    nlink_t nlink;
    int is_symlink;
    struct FileEntry *next;
}FileEntry;

typedef struct{
    char md5[33];
    FileEntry *filepath;
    UT_hash_handle hh;
} FileHash;
// open ssl, this will be used to get the hash of the file
EVP_MD_CTX *mdctx;
const EVP_MD *EVP_md5(); // use md5 hash!!

FileHash *file_hashes = NULL;

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
void print_duplicates()
{
    FileHash *entry, *tmp;
    int file_index = 1;

    HASH_ITER(hh, file_hashes, entry, tmp){
        int count = 0;

        for (FileEntry *fe = entry->filepath; fe != NULL; fe = fe->next)
        {
            count++;
        }

        if (count <= 1)
        {
            continue;
        }

        printf("File %d\n", file_index++);
        printf("\tMD5 Hash: %s\n", entry->md5);

        int printed_hard_links = 0;
        int printed_symlinks = 0;

        for (FileEntry *fe = entry->filepath; fe != NULL; fe = fe->next)
        {
            if ((!S_ISREG(fe->mode)) || (fe->is_symlink)) continue;

            int already_printed = 0;

            for (FileEntry *check = entry->filepath; check != fe; check = check->next)
            {
                if (fe->inode == check->inode && fe->dev == check->dev)
                {
                    already_printed = 1;
                    break;
                }
            }

            if (already_printed) continue;

            int path_count = 0;

            printf("\tHard Link (%ld): %lu\n", fe->nlink, fe->inode);

            for (FileEntry *inner = entry->filepath; inner != NULL; inner = inner->next)
            {
                if (S_ISREG(inner->mode) && !inner->is_symlink && inner->inode == fe->inode && inner->dev == fe->dev)
                {
                    if (path_count == 0)
                    {
                        printf("\t\t\tPaths:\t%s\n", inner->filepath);
                    }

                    else
                    {
                        printf("\t\t\t\t%s\n", inner->filepath);
                    }
                    path_count++;
                }

            }
            printed_hard_links++;
        }

        int soft_link_group = 1;
        for (FileEntry *fe = entry->filepath; fe != NULL; fe = fe->next)
        {
            //printf("hello!\n");

            //printf("hello!\n");
            if (!fe->is_symlink) continue;

            int already_printed = 0;

            for (FileEntry *check = entry->filepath; check != fe; check = check->next)
            {
                //printf("hello!\n");

                if (check->is_symlink && fe->is_symlink && fe->filepath && strcmp(check->filepath, fe->filepath) == 0)
                {
                    already_printed = 1;
                    break;
                }
            }

            if (already_printed) continue;

            int path_count = 0;
            int count = 0;

            for (FileEntry *inner = entry->filepath; inner != NULL; inner = inner->next)
            {
                if ((inner->is_symlink))
                {
                    count++;
                }
            }

            printf("\t\t\tSoft Link %d(%d): %lu\n", soft_link_group++, count, fe->inode);
            for (FileEntry *inner = entry->filepath; inner != NULL; inner = inner->next)
            {
                if (inner->is_symlink){
                    if (path_count == 0)
                    {
                        printf("\t\t\t\tPaths:\t%s\n", inner->filepath);
                    }
                    else
                    {
                        printf("\t\t\t\t\t%s\n", inner->filepath);
                    }
                    path_count++;
                }
            }

            printed_symlinks++;
        }
    }


}


int main(int argc, char *argv[]) {
    // perform error handling, "exit" with failure incase an error occurs

    int r = nftw(argv[1], render_file_info, 10, FTW_PHYS);

    print_duplicates();

    //print_md5(file_hash->md5);
    //printf("hello");

    // initialize the other global variables you have, if any

    // add the nftw handler to explore the directory
    // nftw should invoke the render_file_info function
}
int is_duplicate(const char *md5, const char *filepath, const struct stat *sb)
{
    FileHash *entry = NULL;
    HASH_FIND_STR(file_hashes, md5, entry);

    if (!entry){
        entry = malloc(sizeof(FileHash));
        strncpy(entry->md5, md5, 33);
        entry->filepath = NULL;
        HASH_ADD_STR(file_hashes, md5, entry);
        //printf("not duplicate, has been added!\n");
    }

    FileEntry *new_file = malloc(sizeof(FileEntry));
    new_file->filepath = strdup(filepath);
    new_file->inode = sb->st_ino;
    new_file->dev = sb->st_dev;
    new_file->mode = sb->st_mode;
    new_file->nlink = sb->st_nlink;
    new_file->next = entry->filepath;
    new_file->is_symlink = S_ISLNK(sb->st_mode);
    entry->filepath = new_file;

    //printf("%d\n", new_file->is_symlink);

    return 0;
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
        char real_target[PATH_MAX];

        // Resolve symlink path
        ssize_t len = readlink(fpath, real_target, sizeof(real_target) - 1);
        if (len != -1) {
            real_target[len] = '\0';  // Null-terminate the real target path

            // Compute MD5 hash of the symlink target
            char md5[33];
            compute_md5(real_target, md5);

            if (md5[0] != '\0') {
                is_duplicate(md5, fpath, &target);  // Call is_duplicate for symlinks
            }
        }
    }


        /*struct stat newSb;
        struct stat target;

        char symPath[PATH_MAX];
        ssize_t len = readlink(fpath, symPath, sizeof(symPath - 1));

        if (realpath(fpath, symPath) != NULL)
        {

            if (stat(symPath, &target) == 0 && S_ISREG(target.st_mode))
            {

                    char md5[33];
                    compute_md5(symPath, md5);

                    if (md5[0] != '\0')
                    {
                        is_duplicate(md5, fpath, &target);
                    }
                
            }
        }*/

    

    return 0;

    // invoke any function that you may need to render the file information
}



// add any other functions you may need over here
