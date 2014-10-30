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


/* Flags for handling output and other user decidable things */
#define FLAG_NONE 0
#define FLAG_CSV  1


static void usage(const char *execname)
{
    printf("Usage: %s <obj or exec> [-c]\n"
           "  <obj | exec | lib>: path to the ELF binary to examine\n"
           "  -c                : CSV output\n",
            execname);
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

                         
/* Output a section in the desired format */
static void print_sect(
    int                  instance,
    const char          *fname,
    const char          *sect_name,
    size_t               size,
    const unsigned char *hash,
    int                  flags)
{
    int i;

    if (strlen(sect_name) == 0)
      sect_name = "<none>";

    if (flags & FLAG_CSV)
      printf("%s, %s, %zu, ", fname, sect_name, size);
    else /* Else: Normal output (not csv) */
      printf("% 3d) %-20s", instance, sect_name);

    /* Output the hash */
    printf(" <0x");
    for (i=0; i<160/8; ++i)
      printf("%02x", hash[i]);
    printf("> ");
    
    if (!(flags & FLAG_CSV))
      printf("[%zu bytes]", size);

    putc('\n', stdout);
}


static void disp_sections(FILE *fp, const char *fname, int flags)
{
    int i, n_sections, bits;
    void *hdr, *shdr;
    long here;
    uint64_t strtbl_idx, shent_sz, sect_sz;
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

    /* Header */
    if (flags & FLAG_CSV)
      printf("# Filename, Section Name, Size, SHA1 Hash\n");
    else
      printf("%s: %d sections:\n", fname, n_sections);

    /* For each section ... */
    fseek(fp, E(Ehdr, e_shoff, bits, hdr), SEEK_SET);
    for (i=0; i<n_sections; ++i)
    {
        safe_fread(shdr, shent_sz, fp);
        name = strtbl + E(Shdr, sh_name, bits, shdr);
        sect_sz = (uint64_t)E(Shdr, sh_size, bits, shdr);

        /* Read the data */
        if (!(data = malloc(E(Shdr, sh_size, bits, shdr))))
          ERR("Could not allocate enough memory to store section data");
        here = ftell(fp);
        fseek(fp, E(Shdr, sh_offset, bits, shdr), SEEK_SET);
        safe_fread(data, E(Shdr, sh_size, bits, shdr), fp);
        fseek(fp, here, SEEK_SET);

        /* Calc the hash (160 bits) */
        SHA1(data, E(Shdr, sh_size, bits, shdr), hash);

        print_sect(i+1, fname, name, sect_sz, hash, flags);
    }

    free(shdr);
    free(strtbl);
    strtbl = NULL;
}


int main(int argc, char **argv)
{
    int i, flags;
    FILE *fp;
    const char *fname;

    flags = FLAG_NONE;
    fname = NULL;

    for (i=1; i<argc; ++i)
    {
        if (strncmp("-c", argv[i], 2) == 0)
          flags |= FLAG_CSV;
        else
          fname = argv[i];
    }

    if (!fname)
      usage(argv[0]);

    if (!(fp = fopen(fname, "r")))
      ERR("Could not open file: %s", fname);

    disp_sections(fp, fname, flags);

    fclose(fp);
    return 0;
}
