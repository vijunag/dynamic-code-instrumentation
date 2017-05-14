/*
 * Author: Vijay Nag
 */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#define ROUND_DOWN(_addr, _sz) \
         (((unsigned long)(_addr)) & ~(_sz - 1))

#define ROUND_UP(_addr, _sz) \
        ((((unsigned long)(_addr)) + (_sz)) & ~(_sz-1))

#ifndef IS_ELF
#define IS_ELF(ehdr)  ((ehdr).e_ident[EI_MAG0] == ELFMAG0 && \
       (ehdr).e_ident[EI_MAG1] == ELFMAG1 && \
       (ehdr).e_ident[EI_MAG2] == ELFMAG2 && \
       (ehdr).e_ident[EI_MAG3] == ELFMAG3)
#endif /*IS_ELF*/

#define GET_PHDR_COUNT(type, e)          \
({                                       \
  Elf##type##_Ehdr* _e = &(e);           \
  _e->e_phnum;                           \
})

#define SYSCALL_EXIT_ON_ERR(syscall)                          \
({                                                            \
 int ret = syscall;                                           \
 if (ret < 0) {                                               \
   fprintf(stderr, "%s error at %s:%d, errno(%d) = %s\n",     \
      #syscall, __func__, __LINE__,errno, strerror(errno));   \
    exit(ret);                                                \
 }                                                            \
 ret;                                                         \
 })

#define LOGERR_EXIT(msg) \
do {                     \
  fprintf(stderr, msg);  \
  exit(-1);              \
} while(0);

#define LOG_MSG(msg,...) \
  fprintf(stderr, msg, ##__VA_ARGS__);

int jumpFromHere(void)
{
  int a = 1;
  int b[100];
  printf("DUD!!!I am not going to be here\n");
  printf("I will return something....\n");
}

int jumpTo(void)
{
  printf("I have jumped to this location now\n");
  return 5;
}


typedef struct Elf_ctxt {
  union {
   Elf32_Ehdr elf32_ehdr;
   Elf64_Ehdr elf64_ehdr;
   unsigned char e_ident[EI_NIDENT];
  } elf_ehdr;
#define elf32_ehdr elf_ehdr.elf32_ehdr
#define elf64_ehdr elf_ehdr.elf64_ehdr
#define e_ident    elf_ehdr.e_ident
  void *mmap_addr;
  uint8_t is32; /* is it 32 bit elf ? */
} Elf_ctxt;
static Elf_ctxt g_ctxt;

static int LoadElfFile(const char *file, Elf_ctxt *elf)
{
  struct stat st;
  int fd = SYSCALL_EXIT_ON_ERR(open(file, O_RDONLY));
  SYSCALL_EXIT_ON_ERR(fstat(fd, &st));

  /* read the elf header from the core
   * and mmap it only if it is an elf
   */
  size_t sz = SYSCALL_EXIT_ON_ERR(read(fd, elf, sizeof(elf->elf_ehdr)));
  if (sizeof(elf->elf_ehdr) != sz) {
    LOGERR_EXIT("Cannot read the elf header\n");
  }
  if (!IS_ELF(*elf)) {
    LOGERR_EXIT("Not an ELF\n");
  }

  if (elf->e_ident[EI_CLASS] == ELFCLASS32) {
    elf->is32 = 1;
  } else if (elf->e_ident[EI_CLASS] == ELFCLASS64) {
  } else {
    LOGERR_EXIT("Invalid elf type\n");
  }

  elf->mmap_addr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (elf->mmap_addr < 0) {
    LOGERR_EXIT("File mapping error\n");
  }
}

static void*
elf_find_shdr(Elf_ctxt *elf, char *name, int idx)
{
  char *shstrtab;
  int i;

#define CODE(X)                                        \
  Elf##X##_Ehdr *e = elf->mmap_addr;                   \
  Elf##X##_Shdr *sh;                                   \
  if (e->e_shoff == 0)                                 \
    return (NULL);                                     \
  sh = (Elf##X##_Shdr *)((char *)e + e->e_shoff);      \
  shstrtab = (char *)e + sh[e->e_shstrndx].sh_offset;  \
  for (i = idx; i < e->e_shnum; i++) {                 \
    if (strcmp(name, shstrtab + sh[i].sh_name) == 0)   \
      return (&sh[i]);                                 \
  }                                                    \

  if (elf->is32) {
    CODE(32);
  } else {
    CODE(64);
  }
  return (NULL);
#undef CODE
}

static int
elf_find_sym_by_name(Elf_ctxt *ctx, char *name,
                     unsigned long *val, size_t *sz)
{
#define CODE(X)                                         \
  Elf##X##_Ehdr *e = ctx->mmap_addr;                    \
  Elf##X##_Shdr *sh;                                    \
  Elf##X##_Sym *st;                                     \
  char *strtab;                                         \
  int i;                                                \
  if ((sh = elf_find_shdr(ctx, ".strtab", 0)) == NULL)  \
    return (0);                                         \
  strtab = (char *)e + sh->sh_offset;                   \
  if ((sh = elf_find_shdr(ctx, ".symtab", 0)) == NULL)  \
    return (0);                                         \
  st = (Elf##X##_Sym *)((char *)e + sh->sh_offset);     \
  for (i = 0; i < sh->sh_size / sizeof(*st); i++) {     \
    if (strcmp(name, strtab + st[i].st_name) == 0)      \
      *val =  (st[i].st_value);                         \
      *sz = st[i].st_size;                              \
  }                                                     \

  if (ctx->is32) {
    CODE(32);
  } else {
    CODE(64);
  }
#undef CODE
}

/* Replace function f1 with f2 */
void ReplaceFunction(char *func, const void *f2)
{
  int pagesize = sysconf(_SC_PAGE_SIZE);
  unsigned long from_addr, to_addr = (unsigned long)f2;
  unsigned long jmp_addr = 0;
  size_t sz = 0;

  int retval = elf_find_sym_by_name(&g_ctxt, func, &from_addr, &sz);
  if (!retval) {
    printf("No such symbol\n");
    exit(-1);
  }
  sz = (size_t)ROUND_UP(sz, pagesize);
  SYSCALL_EXIT_ON_ERR(mprotect((void*)ROUND_DOWN(from_addr, pagesize),
        sz, PROT_READ|PROT_WRITE|PROT_EXEC));
  jmp_addr = 0-(from_addr-to_addr) - 5;
  *(unsigned char*)from_addr = 0xE9;
  *(unsigned int*)(((unsigned char*)from_addr)+1) = (unsigned int)jmp_addr;
}

int main()
{
  int pagesize;
  char func_name[256];
  int retval = -1;

#ifdef linux
  LoadElfFile("/proc/self/exe", &g_ctxt);
#else /*best effort service on other platforms*/
  LoadElfFile("/proc/curproc/file", &g_ctxt);
#endif

  printf("Enter the function name to override\n");
  scanf("%s", &func_name[0]);

  ReplaceFunction(func_name, &jumpTo);
  printf("jumpFromHere() returned --->%d\n", jumpFromHere());
}

