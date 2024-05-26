.PHONY : all

all : kvmstringreverse guest

kvmstringreverse : kvmstringreverse.c
	gcc -O2 -std=gnu2x -Wall -Wextra -march=native -okvmstringreverse kvmstringreverse.c

guest : guest.asm
	nasm -fbin guest.asm
