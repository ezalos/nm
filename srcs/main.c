#include "head.h"
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

static int	usage()
{
	ft_printf("Usage: nm <file>\n");
	return (EXIT_SUCCESS);
}

int			 main(int ac, char **av)
{
	int		res;
	t_nm	nm;

	#if !__MACH__ && !__linux__
	ft_printf("Supported systems: MacOS, Linux\n");
	return (EXIT_FAILURE);
	#endif

	if (ac < 2)
		return usage();

	if ((nm.fd = open(av[1], O_RDONLY)) < 0)
		return ft_perror("open");
	if (fstat(nm.fd, &(nm.stat)) < 0)
		return ft_perror("fstat");
	if ((nm.mapfile = (uint8_t*)mmap(0, nm.stat.st_size, PROT_READ, MAP_PRIVATE, nm.fd, 0)) == MAP_FAILED)
		return ft_perror("mmap");

	#if __MACH__
		res = main_macos(&nm);
	#elif __linux__
		res =  main_linux(&nm);
	#endif
	munmap(nm.mapfile, nm.stat.st_size);
	close(nm.fd);
	return res;
}
