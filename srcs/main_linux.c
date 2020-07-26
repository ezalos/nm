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

void	print_type(Elf64_Sym sym)
{
	if (sym.st_info == STT_NOTYPE)
		ft_printf("STT_NOTYPE  ");
	else if (sym.st_info == STT_OBJECT)
		ft_printf("STT_OBJECT  ");
	else if (sym.st_info == STT_FUNC)
		ft_printf("STT_FUNC    ");
	else if (sym.st_info == STT_SECTION)
		ft_printf("STT_SECTION ");
	else if (sym.st_info == STT_FILE)
		ft_printf("STT_FILE    ");
	else if (sym.st_info == STT_LOPROC)
		ft_printf("STT_LOPROC  ");
	else if (sym.st_info == STT_HIPROC)
		ft_printf("STT_HIPROC  ");
	else if (sym.st_info == STB_LOCAL)
		ft_printf("STB_LOCAL   ");
	else if (sym.st_info == STB_GLOBAL)
		ft_printf("STB_GLOBAL  ");
	else if (sym.st_info == STB_WEAK)
		ft_printf("STB_WEAK    ");
	else if (sym.st_info == STB_LOPROC)
		ft_printf("STB_LOPROC  ");
	else if (sym.st_info == STB_HIPROC)
		ft_printf("STB_HIPROC  ");
	else
		ft_printf("st_info %-3u ", sym.st_info);
}

/*
**
**	HEADER 1/2 : Technical details for identification and execution
**
**		Elf Header
**		Struct : Elf64_Ehdr
**
**		Program Header table
**		Struct : Elf64_Phdr
**			execution information : to_load, size, rights,...
**
**
**	SECTIONS : Contents of the executable
**
**		Code
**			executable information
**
**		Data
**			Information used by the code
**
**		Sections' names
**
**
**	HEADER 1/2 : Technical details for linking (ignored at execution)
**
**		Section Header Table
**		Struct : Elf64_Shdr
**			Linking (Connecting program objects) information
**			sh_name : offset to read string in 'Sections' names'
**
*/

void new_try(Elf64_Ehdr *elf, void *data)
{
	// Elf64_Shdr
	// A file's section header table lets one locate all the file's sections.
	//	 The section header table is an array of Elf32_Shdr or Elf64_Shdr structures.
	//	 The ELF header's e_shoff member gives the byte offset from the beginning of the file to the section header table.
	//	 e_shnum holds the number of entries the section header table contains. e_shentsize holds the size in bytes of each entry.
	//	 A section header table index is a subscript into this array.
	Elf64_Shdr      *symtab;
	Elf64_Shdr      *shstrtab;
	Elf64_Shdr      *strtab;
	int				i;

	// e_shoff
	// This member holds the section header table's file offset in bytes.
	Elf64_Shdr      *section_header = (Elf64_Shdr *) (data + elf->e_shoff); //section names is after data

	// sh_offset
	// 	This member's value holds the byte offset from the beginning of the file to the first byte in the section.
	// e_shstrndx
	//	This member holds the section header table index of the entry associated with the section name string table.
	char            *section_names = (char *) (data + section_header[elf->e_shstrndx].sh_offset);

	// Various sections hold program and control information:
	// we are looking through section names to locate the section of interest (symbol table)

	// ft_printf("%~{255;155;255}");
	i = -1;
	while (++i < elf->e_shnum) // number of entries in the section header table
	{
		if (section_header[i].sh_size) // holds the section's size in bytes
		{
			// ft_printf("%s\n", &section_names[section_header[i].sh_name]);
			if (section_header[i].sh_type == SHT_SYMTAB){
				ft_printf("Symbol Table !\n\ti: %d\n\tname : %p\n\t thing %s\n", i, section_header[i].sh_name, &section_names[section_header[i].sh_name]);}

			// This section holds a symbol table.
    		if (ft_strcmp(&section_names[section_header[i].sh_name], ".symtab") == 0){
      			symtab = (Elf64_Shdr *) &section_header[i];}

			// This section holds section names. (which is itself right now, i guess)
   			if (ft_strcmp(&section_names[section_header[i].sh_name], ".shstrtab") == 0){
     			shstrtab = (Elf64_Shdr *) &section_header[i];}

			// This section holds strings, most commonly the strings that represent the names associated with symbol table entries.
    		if (ft_strcmp(&section_names[section_header[i].sh_name], ".strtab") == 0){
      			strtab = (Elf64_Shdr *) &section_header[i];}
  		}
	}
	(void)shstrtab;

	// Elf64_Sym
	// 	An object file's symbol table holds information needed to locate and relocate a program's symbolic definitions and references.
	// 	A symbol table index is a subscript into this array.
	//		st_name : holds offset to read in
	Elf64_Sym *sym = (Elf64_Sym*) (data + symtab->sh_offset);
	section_names = (char*) (data + strtab->sh_offset);

	ft_printf("%~{155;255;255}");
	i = -1;
	while ((size_t)++i < symtab->sh_size / symtab->sh_entsize) /* was 'symtab->sh_size / sizeof(Elf64_Sym)' before */
	{
		if (sym[i].st_info != STT_SECTION && sym[i].st_info != STT_NOTYPE)
		{
			ft_printf("%016x ", elf->e_shoff + (sym[i].st_shndx * elf->e_shentsize));// not good yet
			print_type(sym[i]);
	 		ft_printf("%s\n", section_names + sym[i].st_name);
		}
	}
	ft_printf("%~{}");
}

int main_linux(t_nm *nm)
{
	if (elf_check_file((Elf64_Ehdr *)nm->content) == TRUE)
	{
		ft_printf("Good magic number!\n");
		elf_check_machine((Elf64_Ehdr *)nm->content);
		if (elf_check_supported((Elf64_Ehdr *)nm->content) == TRUE)
		{
			ft_printf("File is supported!\n");
			// print_sym_tab((Elf64_Ehdr *)nm->content);
			new_try((Elf64_Ehdr *)nm->content, nm->content);
		}

	}
	return (EXIT_SUCCESS);
}
