/*
https://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx

http://fileformats.archiveteam.org/wiki/Authenticode_signature

.p7b file, can be viewed by certmgr.msc
https://en.wikipedia.org/wiki/X.509#Certificate_filename_extensions
*/

#include <stdio.h>
#include <stdlib.h>

#include <windows.h>

char *strcat_x(char *path, char *ext_path) {
    path = realloc(path, strlen(path) + strlen(ext_path) + 1);
    return strcat(path, ext_path);
}

int main(int argc, char *argv[])
{
    int i;
    FILE *fp = NULL, *fp_w = NULL;
    IMAGE_DOS_HEADER dos_hdr;
    IMAGE_NT_HEADERS nt_hdr;
    IMAGE_DATA_DIRECTORY  *p_certificate_table;
    char *fname_p2b;
    unsigned char *p2b;
    DWORD size_p2b;
    //
    if (argc < 2) {
        printf("%s <pe-file> ...\n", argv[0]);
        return 1;
    }
    //
    for (i = 1; i < argc; i++) {
        WORD e_magic = 0;
        int fd;
        long file_size;
        BYTE *pe_file, *section;
        int not_pe = 1, good = 0;
        long j, n;
        //
        printf("\"%s\"\t", argv[i]);
        //
        fp = fopen(argv[i], "r+b");
        if (fp == NULL) {
            printf("fail-read\n");
            continue;
        }
        // pre-test
        fread(&e_magic, 1, sizeof(WORD), fp);
        if (e_magic != 0x5A4D) {
            printf("not-pe-file, ");
            goto access_decision;
        }
        // main-test
        rewind(fp);
        fread(&dos_hdr, 1, sizeof(IMAGE_DOS_HEADER), fp);
        fseek(fp, dos_hdr.e_lfanew, SEEK_SET);
        fread(&nt_hdr, 1, sizeof(IMAGE_NT_HEADERS), fp);
        //
        if (nt_hdr.Signature != 0x4550) {
            printf("not-pe-file, ");
            goto access_decision;
        }
        not_pe = 0;
        //
        p_certificate_table = nt_hdr.OptionalHeader.DataDirectory + 4;
        if (p_certificate_table->Size > 0) {
            good = 1;
        }
        else {
            printf("no-authenticode\n");
            goto access_decision;
        }
        //
access_decision:
        if (good) {
            fseek(fp, p_certificate_table->VirtualAddress + 8, SEEK_SET);
            //
            size_p2b = p_certificate_table->Size - 8;
            p2b = malloc(size_p2b);
            fread(p2b, 1, size_p2b, fp);
            //
            fname_p2b = strdup(argv[i]);
            fname_p2b = strcat_x(fname_p2b, ".p7b");
            fp_w = fopen(fname_p2b, "w+b");
            if (fp_w == NULL) {
                printf("fail-write\n");
                goto cleanup;
            }
            fwrite(p2b, 1, size_p2b, fp_w);
            fflush(fp_w);
            printf("succeed\n");
        }
        //
cleanup:
        free(p2b);
        free(fname_p2b);
        if (fp) fclose(fp);
        if (fp_w) fclose(fp_w);
    }
    //
    return 0;
}