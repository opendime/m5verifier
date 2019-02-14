# Makefile

all:
	@echo "no default target"

tags:
	ctags -f .tags --langmap=c++:.ino *.ino *.[ch]

