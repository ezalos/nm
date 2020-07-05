#ifdef __MACH__

#include "head.h"
#include "nmruntime.h"
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

char	*get_type_name(t_nlist64 *symbol)
{
	uint32_t	n_type;

	n_type = symbol->n_type & N_TYPE;

	if(n_type == N_UNDF)
		return "U";
	else if (n_type == N_ABS)
		return "N_ABS";
	else if (n_type == N_SECT)
		return "T";
	else if (n_type == N_PBUD)
		return "N_PBUD";
	else if (n_type == N_INDR)
		return "N_INDR";
	else
		return "Undefined";
}

void	print_output64(t_nm *nm, t_symtab_cmd *sym)
{
	int			i;
	char		*strtable;
	t_nlist64	*ls;
	char		*name;

	ls = (t_nlist64*)((uint8_t*)nm->mapfile + sym->symoff);
	strtable = (char*) nm->mapfile + sym->stroff;
	i = -1;
	while (++i < (int)sym->nsyms)
	{
		name = strtable + ls[i].n_un.n_strx;
		//uint32_t  n_strx; /* index into the string table */
		// Means that strtable + ls[i].n_un.n_strx -> char* index name
		//uint8_t n_type;        /* type flag, see below */
		/* n_type is used with these masks :
		N_STAB, N_PEXT, N_TYPE, N_EXT */

		//uint8_t n_sect;        /* section number or NO_SECT */
		//uint16_t n_desc;       /* see <mach-o/stab.h> */
		//uint64_t n_value;

		/*ft_printf("name = %s\n", name);
		ft_printf("type = %d\n", ls[i].n_type);
		ft_printf("\tN_STAB = %d\n", ls[i].n_type & N_STAB);
		ft_printf("\tN_PEXT = %d\n", ls[i].n_type & N_PEXT);
		ft_printf("\tN_TYPE = %d\n", ls[i].n_type & N_TYPE);
		ft_printf("\t\t-> %s\n", get_type_name(ls + i));
		ft_printf("\tN_EXT = %d\n", ls[i].n_type & N_EXT);
		ft_printf("sect = %d\n", ls[i].n_sect);
		ft_printf("desc = %d\n", ls[i].n_desc);
		ft_printf("value = %llx\n", ls[i].n_value);
		ft_printf("--------------\n", ls[i].n_value);*/

		if ((ls[i].n_type & N_TYPE) == N_UNDF)
			ft_printf("%16s %s %s\n", "", get_type_name(ls + i), name);
		else
			ft_printf("%016llx %s %s\n", ls[i].n_value, get_type_name(ls + i), name);
	}
}

void	handle64(t_nm *nm)
{
	uint32_t		i;
	t_header_64		*header;
	t_loadcmd		*lc;
	t_symtab_cmd	*sym;

	header = (t_header_64*)nm->mapfile;
	i = 0;
	lc = (t_loadcmd*)((uint8_t*)nm->mapfile + sizeof(t_header_64));
	while (i < header->ncmds)
	{
		if (lc->cmd == LC_SYMTAB) {
			sym = (t_symtab_cmd*)lc;
			print_output64(nm, sym);
			break;
		}
		lc = (t_loadcmd*)((uint8_t*)lc + lc->cmdsize);
		i++;
	}
}

int		main_macos(t_nm *nm)
{
	uint32_t magic;

	magic = *((int *) nm->mapfile);

	if (magic == MH_MAGIC_64)
		handle64(nm);

	return (EXIT_SUCCESS);
}

#endif
