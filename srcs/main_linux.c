#include "head.h"
#include <elf.h>
#include "nmruntime.h"


static int	ft_perror(char *msg)
{
	#if DEBUG
	perror(msg);
	#elif
	ft_printf("Error: %s\n", msg);
	#endif
	return (EXIT_FAILURE);
}

void elf_check_machine(Elf64_Ehdr *hdr)
{
	if(hdr->e_machine == EM_NONE)
		ft_printf("Une machine inconnue.");
	if(hdr->e_machine == EM_M32)
		ft_printf("Un WE 32100 d'AT&T.");
	if(hdr->e_machine == EM_SPARC)
		ft_printf("Un SPARC de Sun Microsystems.");
	if(hdr->e_machine == EM_386)
		ft_printf("Un 80386 d'Intel.");
	if(hdr->e_machine == EM_68K)
		ft_printf("Un 68000 de Motorola.");
	if(hdr->e_machine == EM_88K)
		ft_printf("Un 88000 de Motorola.");
	if(hdr->e_machine == EM_860)
		ft_printf("Un 80860 d'Intel.");
	if(hdr->e_machine == EM_MIPS)
		ft_printf("Un RS3000 de MIPS (uniquement gros boutien).");
	if(hdr->e_machine == EM_PARISC)
		ft_printf("Un HP/PA.");
	if(hdr->e_machine == EM_SPARC32PLUS)
		ft_printf("Un SPARC avec jeu d'instructions amélioré.");
	if(hdr->e_machine == EM_PPC)
		ft_printf("Un PowerPC.");
	if(hdr->e_machine == EM_PPC64)
		ft_printf("Un PowerPC 64 bits.");
	if(hdr->e_machine == EM_S390)
		ft_printf("Un S/390 d'IBM.");
	if(hdr->e_machine == EM_ARM)
		ft_printf("Un ARM.");
	if(hdr->e_machine == EM_SH)
		ft_printf("Un SuperH de Renesas.");
	if(hdr->e_machine == EM_SPARCV9)
		ft_printf("Un SPARC v9 64 bits.");
	if(hdr->e_machine == EM_IA_64)
		ft_printf("Un Itanium d'Intel.");
	if(hdr->e_machine == EM_X86_64)
		ft_printf("Un x86-64 d'AMD.");
	if(hdr->e_machine == EM_VAX)
		ft_printf("Un Vax de DEC.");
	ft_printf("\n");
}


uint8_t elf_check_file(Elf64_Ehdr *hdr) {
	if(!hdr)
	{
		return FALSE;
	}
	if(hdr->e_ident[EI_MAG0] != ELFMAG0)
	{
		ft_perror("ELF Header EI_MAG0 incorrect.\n");
		return FALSE;
	}
	if(hdr->e_ident[EI_MAG1] != ELFMAG1)
	{
		ft_perror("ELF Header EI_MAG1 incorrect.\n");
		return FALSE;
	}
	if(hdr->e_ident[EI_MAG2] != ELFMAG2)
	{
		ft_perror("ELF Header EI_MAG2 incorrect.\n");
		return FALSE;
	}
	if(hdr->e_ident[EI_MAG3] != ELFMAG3)
	{
		ft_perror("ELF Header EI_MAG3 incorrect.\n");
		return FALSE;
	}
	return TRUE;
}

uint8_t elf_check_supported(Elf64_Ehdr *hdr)
{
	if(!elf_check_file(hdr))
	{
		ft_perror("Invalid ELF File.\n");
		return FALSE;
	}
	if(hdr->e_ident[EI_CLASS] != ELFCLASS64)
	{
		ft_perror("Unsupported ELF File Class.\n");
		return FALSE;
	}
	if(hdr->e_ident[EI_DATA] != ELFDATA2LSB)
	{
		ft_perror("Unsupported ELF File byte order.\n");
		return FALSE;
	}
	if(hdr->e_machine != EM_X86_64)
	{
		ft_perror("Unsupported ELF File target.\n");
		return FALSE;
	}
	if(hdr->e_ident[EI_VERSION] != EV_CURRENT)
	{
		ft_perror("Unsupported ELF File version.\n");
		return FALSE;
	}
	if(hdr->e_type != ET_REL && hdr->e_type != ET_DYN && hdr->e_type != ET_EXEC)
	{
		ft_perror("Unsupported ELF File type.\n");
		return FALSE;
	}
	return TRUE;
}

static inline Elf64_Shdr *elf_sheader(Elf64_Ehdr *hdr)
{
	return (Elf64_Shdr *)((uint64_t)hdr + hdr->e_shoff);
}

static inline Elf64_Shdr *elf_section(Elf64_Ehdr *hdr, int idx)
{
	return &elf_sheader(hdr)[idx];
}

static inline char *elf_str_table(Elf64_Ehdr *hdr) {
	if(hdr->e_shstrndx == SHN_UNDEF)
		return NULL;
	return (char *)hdr + elf_section(hdr, hdr->e_shstrndx)->sh_offset;
}

static inline char *elf_lookup_string(Elf64_Ehdr *hdr, int offset) {
	char *strtab = elf_str_table(hdr);

	if(strtab == NULL)
		return NULL;
	return strtab + offset;
}

#define ELF_RELOC_ERR -1

int elf_get_symval(Elf64_Ehdr *hdr, int table, uint idx)
{
	if(table == SHN_UNDEF || idx == SHN_UNDEF) return 0;
		Elf64_Shdr *symtab = elf_section(hdr, table);

	uint64_t symtab_entries = symtab->sh_size / symtab->sh_entsize;
	if(idx >= symtab_entries)
	{
		ft_printf("Symbol Index out of Range (%d:%u).\n", table, idx);
		return ELF_RELOC_ERR;
	}
	uint64_t symaddr = (uint64_t)hdr + symtab->sh_offset;
	Elf64_Sym *symbol = &((Elf64_Sym *)symaddr)[idx];
	if(symbol->st_shndx == SHN_UNDEF)
	{
		// External symbol, lookup value
		Elf64_Shdr *strtab = elf_section(hdr, symtab->sh_link);
		const char *name = (const char *)hdr + strtab->sh_offset + symbol->st_name;

		// Extern symbol not found
		if(ELF64_ST_BIND(symbol->st_info) & STB_WEAK)
		{
			// Weak symbol initialized as 0
			return 0;
		}
		else
		{
			ft_printf("Undefined External Symbol : %s.\n", name);
			return ELF_RELOC_ERR;
		}
	}
	else if(symbol->st_shndx == SHN_ABS)
	{
		// Absolute symbol
		return symbol->st_value;
	}
	else
	{
		// Internally defined symbol
		Elf64_Shdr *target = elf_section(hdr, symbol->st_shndx);
		return (uint64_t)hdr + symbol->st_value + target->sh_offset;
	}
	return (0);
}


void new_try(Elf64_Ehdr *elf, void *data)
{
	Elf64_Shdr      *shdr = (Elf64_Shdr *) (data + elf->e_shoff);
	Elf64_Shdr      *symtab;
//	Elf64_Shdr      *shstrtab;
	Elf64_Shdr      *strtab;
	char            *str = (char *) (data + shdr[elf->e_shstrndx].sh_offset);

	for (int i = 0; i < elf->e_shnum; i++)
	{
		if (shdr[i].sh_size)
		{
    		printf("%s\n", &str[shdr[i].sh_name]);
    		if (ft_strcmp(&str[shdr[i].sh_name], ".symtab") == 0)
      			symtab = (Elf64_Shdr *) &shdr[i];
 //   		if (ft_strcmp(&str[shdr[i].sh_name], ".shstrtab") == 0)
 //     			shstrtab = (Elf64_Shdr *) &shdr[i];
    		if (ft_strcmp(&str[shdr[i].sh_name], ".strtab") == 0)
      			strtab = (Elf64_Shdr *) &shdr[i];
  		}
	}

//	str = (char *) shstrtab;
//	for (size_t i = 0; i < (symtab->sh_size / sizeof(Elf64_Sym *)); i ++) 
//	{
//  		printf("%s\n", &str[shstrtab[i].sh_name]);
//	}

	Elf64_Sym *sym = (Elf64_Sym*) (data + symtab->sh_offset);
	str = (char*) (data + strtab->sh_offset);
	for (size_t i = 0; i < symtab->sh_size / sizeof(Elf64_Sym); i++)
	{
 		printf("%s\n", str + sym[i].st_name);
	}
}


void print_sym_tab(Elf64_Ehdr *header)
{
	Elf64_Shdr	*sections;
	Elf64_Sym	*symtab;
	int			i;

	ft_printf("Header ptr: %p\n", header);
	sections = (Elf64_Shdr *)((char *)header + header->e_shoff);
	ft_printf("Sectio ptr: %p\n", sections);
	ft_printf("e_shnum : %d\n", header->e_shnum);
	i = -1;
	while (++i < header->e_shnum)
    	if (sections[i].sh_type == SHT_SYMTAB)
		{
        	symtab = (Elf64_Sym *)((char *)header + sections[i].sh_offset);
			ft_printf("[%d] : |%s|\n", i, symtab->st_name);
        }
		else
			ft_printf("[%d] : %d\n", i, sections[i].sh_type);
}

int main_linux(t_nm *nm)
{
//	char *res;
//	int i;

	if (elf_check_file((Elf64_Ehdr *)nm->content) == TRUE)
	{
		ft_printf("Good magic number!\n");
		elf_check_machine((Elf64_Ehdr *)nm->content);
		if (elf_check_supported((Elf64_Ehdr *)nm->content) == TRUE)
		{
			ft_printf("File is supported!\n");
			print_sym_tab((Elf64_Ehdr *)nm->content);
			new_try((Elf64_Ehdr *)nm->content, nm->content);
			// i = 0;
			// while (++i)
			// {
			// 	res = elf_lookup_string((Elf64_Ehdr *)nm->content, i);
			// 	ft_printf("%d|%s|\n", i, res);
			// }
		}

	}
	return (EXIT_SUCCESS);
}
