rm=/bin/rm -f
CC=cc
DEFS=
INCLUDES=-I.
LIBS=

DEFINES= $(INCLUDES) $(DEFS)
CFLAGS= -std=c99 $(DEFINES) -O2 -fomit-frame-pointer -funroll-loops

all: aescopa_driver

aescopa_driver: aescopa_driver.c aes128e.o aescopa.o
	$(CC) $(CFLAGS) -o aescopa_driver aescopa_driver.c aes128e.o aescopa.o $(LIBS)

aes128e.o: aes128e.c
	$(CC) $(CFLAGS) -c aes128e.c $(LIBS)

aescopa.o: aescopa.c
	$(CC) $(CFLAGS) -c aescopa.c $(LIBS)

clean:
	$(rm) aescopa.o aescopa_driver *.o core *~

