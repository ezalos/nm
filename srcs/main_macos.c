#ifdef __MACH__

#include "head.h"
#include "nmruntime.h"
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

void	print_output64(t_nm *nm, t_symtab_cmd *sym)
{
	int			i;
	uint8_t		*strtable;
	t_nlist64	*ls;

	ls = (t_nlist64*)((uint8_t*)nm->mapfile + sym->symoff);
	strtable = (uint8_t*) nm->mapfile + sym->stroff;
	i = -1;
	while (++i < (int)sym->nsyms)
	{
		ft_printf("%s\n", strtable + ls[i].n_un.n_strx);
	}
}

void	handle64(t_nm *nm)
{
	uint32_t	i;
	t_header_64	*header;
	t_loadcmd	*lc;
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
