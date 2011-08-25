asmscan: asmscan.o
	ld -o asmscan asmscan.o
asmscan.o: asmscan.asm
	nasm -f elf -o asmscan.o asmscan.asm
