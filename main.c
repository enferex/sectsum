#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <openssl/sha.h>


#define ERR(...) \
    do { fprintf(stderr,__VA_ARGS__); \
         fputc('\n',stderr);          \
         exit(EXIT_FAILURE);}         \
    while(0)


static void usage(const char *execname)
{
    printf("Usage: %s <obj or exec>\n", execname);
    exit(EXIT_SUCCESS);
}


static size_t safe_fread(void *buf, size_t sz, FILE *fp)
{
    if (fread(buf, 1, sz, fp) != sz)
    {
        if (ferror(fp))
          ERR("Error %d reading from input file", ferror(fp));
        else
          ERR("Could not read requested amount from input file");
    }

    return sz;
}


/* 32/64 Elf structure accessor:
 * _b: Name of the structure following the Elf32 or Elf64 prefix
 * _f: Field of the structure to access
 * _s: Bit size (32 or 64)
 * _p: void * to the structure
 */
#define E(_b, _f, _s, _p) ((_s==32) ? \
    ((Elf32_##_b *) _p)->_f : ((Elf64_##_b *) _p)->_f)

#define E_SZ(_b, _s) ((_s==32) ? \
    sizeof(Elf32_##_b) : sizeof(Elf64_##_b))


static void disp_sections(FILE *fp, const char *fname)
{
    int i, j, n_sections, bits;
    void *hdr, *shdr;
    long here;
    uint64_t strtbl_idx, shent_sz;
    char *strtbl, *name, ident[EI_NIDENT];
    unsigned char hash[32], *data;
    Elf32_Ehdr hdr32 = {{0}};
    Elf64_Ehdr hdr64 = {{0}};

    safe_fread(ident, EI_NIDENT, fp);
    if (strncmp(ident, ELFMAG, strlen(ELFMAG)) != 0)
      ERR("This is not an ELF file");

    if (ident[EI_CLASS] == ELFCLASS32) 
    {
        hdr = (Elf32_Ehdr *)&hdr32;
        bits = 32;
    }
    else if (ident[EI_CLASS] == ELFCLASS64)
    {
        hdr = (Elf64_Ehdr *)&hdr64;
        bits = 64;
    }
    else
      ERR("Unknown binary word-size");

    /* Read the ELF header */
    rewind(fp);
    safe_fread(hdr, E_SZ(Ehdr, bits), fp);
    n_sections = E(Ehdr, e_shnum, bits, hdr);
    strtbl_idx = E(Ehdr, e_shstrndx, bits, hdr);
    shent_sz = E(Ehdr, e_shentsize, bits, hdr);

    /* A temp store for section headers (32 or 64bit agnostic) */
    if (!(shdr = malloc(shent_sz)))
      ERR("Could not allocate enough memory to parse a section header");

    /* Get the section header for the string table */
    fseek(fp, E(Ehdr, e_shoff, bits, hdr) + strtbl_idx * shent_sz, SEEK_SET);
    safe_fread(shdr, shent_sz, fp);

    /* Allocate and read the string table */
    if (!(strtbl = malloc(E(Shdr, sh_size, bits, shdr))))
      ERR("Could not allocate enough memory to store the string table");
    fseek(fp, E(Shdr, sh_offset, bits, shdr), SEEK_SET);
    safe_fread(strtbl, E(Shdr, sh_size, bits, shdr), fp);

    /* For each section ... */
    fseek(fp, E(Ehdr, e_shoff, bits, hdr), SEEK_SET);
    printf("%s: %d sections:\n", fname, n_sections);
    for (i=0; i<n_sections; ++i)
    {
        safe_fread(shdr, shent_sz, fp);
        name = strtbl + E(Shdr, sh_name, bits, shdr);
        printf("% 3d) %-20s", i+1, name[0] ? name : "<none>");

        /* Read the data */
        if (!(data = malloc(E(Shdr, sh_size, bits, shdr))))
          ERR("Could not allocate enough memory to store section data");
        here = ftell(fp);
        fseek(fp, E(Shdr, sh_offset, bits, shdr), SEEK_SET);
        safe_fread(data, E(Shdr, sh_size, bits, shdr), fp);
        fseek(fp, here, SEEK_SET);

        /* Calc the hash */
        SHA1(data, E(Shdr, sh_size, bits, shdr), hash);
        printf(" <0x");
        for (j=0; j<160/8; ++j)
          printf("%02x", hash[j]);
        printf("> [%d bytes]\n", (int)E(Shdr, sh_size, bits, shdr));
    }

    free(shdr);
    free(strtbl);
    strtbl = NULL;
}


int main(int argc, char **argv)
{
    FILE *fp;
    const char *fname;

    if (argc != 2)
      usage(argv[0]);
    fname = argv[1];

    if (!(fp = fopen(fname, "r")))
      ERR("Could not open file: %s", fname);

    disp_sections(fp, fname);

    fclose(fp);
    return 0;
}
