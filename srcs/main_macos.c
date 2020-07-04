#ifdef __MACH__

#include "head.h"
#include "nmruntime.h"
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

void	handle64(t_nm *nm)
{
	int			i;
	t_header_64	*header;
	t_loadcmd	*lc;

	header = (t_header_64*)nm->content;
	i = 0;
	lc = (uint8_t*)nm->content + sizeof(t_header_64);
	while (i < header->ncmds)
	{
		if (lc->cmd == LC_SYMTAB) {
			ft_printf("Good\n");
			break;
		}
		lc = (uint8_t*)lc + lc->cmdsize;
		i++;
	}
}

int		main_macos(t_nm *nm)
{
	int magic;

	magic = *((int *) nm->content);

	if (magic == MH_MAGIC_64)
		handle64(nm);

	(void)nm;
	ft_printf("Hello on MacOS\n");
	return (EXIT_SUCCESS);
}

#endif
