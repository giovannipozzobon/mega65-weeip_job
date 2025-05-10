cls
del .\mega65\obj\*.o
del .\weeip\obj\*.o
del .\obj\*.o
del .\obj\*.prg
cd .\mega65\src
cc6502 -O2 --target=mega65 memory.c -o  ../obj/memory.o
cc6502 -O2 --target=mega65 random.c -o  ../obj/random.o
cc6502 -O2 --target=mega65 debug.c  -o  ../obj/debug.o
cc6502 -O2 --target=mega65 hal.c    -o  ../obj/hal.o
cc6502 -O2 --target=mega65 time.c   -o  ../obj/time.o
cc6502 -O2 --target=mega65 targets.c -o  ../obj/targets.o
cd ..\..
cd .\weeip\src
cc6502 -O2 --target=mega65 arp.c -o  ../obj/arp.o
cc6502 -O2 --target=mega65 checksum.c -o  ../obj/checksum.o
cc6502 -O2 --target=mega65 dhcp.c -o  ../obj/dhcp.o
cc6502 -O2 --target=mega65 dns.c -o  ../obj/dns.o
cc6502 -O2 --target=mega65 eth.c -o  ../obj/eth.o
cc6502 -O2 --target=mega65 nwk.c -o  ../obj/nwk.o
cc6502 -O2 --target=mega65 socket.c -o  ../obj/socket.o
cc6502 -O2 --target=mega65 task.c -o  ../obj/task.o
cd ..\..
cc6502 -O2 --target=mega65 terminal.c -o ./obj/terminal.o
cc6502 -O2 --target=mega65 udptest.c -o ./obj/udptest.o
copy .\mega65\obj\*.o .\obj\
copy .\weeip\obj\*.o .\obj\
cd obj
ln6502 --target=mega65 --core=45gs02 --cstack-size=0x800 --heap-size=4000  --output-format=prg mega65-banked.scm memory.o random.o debug.o hal.o time.o targets.o arp.o checksum.o dhcp.o dns.o eth.o nwk.o socket.o task.o terminal.o -o terminal.prg
ln6502 --target=mega65 --core=45gs02 --cstack-size=0x800 --heap-size=4000  --output-format=prg mega65-banked.scm memory.o random.o debug.o hal.o time.o targets.o arp.o checksum.o dhcp.o dns.o eth.o nwk.o socket.o task.o udptest.o -o udptest.prg
copy terminal.prg ..\terminal.prg
copy udptest.prg ..\udptest.prg
cd ..

