#include "head.h"

int main(int ac, char **av)
{
	int fd;

	if (ac < 2)
	{
		return (EXIT_FAILURE);
	}
	if ((fd = open(av[1], O_RDONLY)) < 0)
	{
		perror("open");
		return (EXIT_FAILURE);
	}
	ft_printf("Wassup\n");
	return (EXIT_SUCCESS);
}
