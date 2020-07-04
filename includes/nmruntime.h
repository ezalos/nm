#ifndef NMRUNTIME_H
#define NMRUNTIME_H

#include <sys/stat.h>

#define DEBUG 1

typedef struct stat t_stat;

typedef struct	s_nm
{
	int		fd;
	uint8_t	*content;
	t_stat	stat;
}				t_nm;

#if __MACH__
int	main_macos(t_nm *nm);
typedef struct mach_header_64 t_header_64;
typedef struct load_command t_loadcmd;
#elif __linux__
int	main_linux(t_nm *nm);
#endif

#endif
