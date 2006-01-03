# ircd-ratbox Windows RSA Respond Tool
# Native mingw32 build..
#
# This likely will need to be edited for your machine
#
# $Id$

all: winrespond.exe

CC=gcc
CFLAGS=-mwindows -O2 -Wall -W -Werror -Wno-unused
LDFLAGS=-static -mwindows
LIBS=-lcrypto -lgdi32
WINDRES=windres
STRIP=strip


winrespond.exe: winrespond.o respond.res
	$(CC) $(LDFLAGS) -o $@ winrespond.o respond.res $(LIBS)

winrespond.o: winrespond.c resource.h
	$(CC) $(CFLAGS) -c winrespond.c

respond.res: respond.rc resource.h
	$(WINDRES) $< -O coff -o $@

strip: winrespond.exe
	$(STRIP) winrespond.exe

clean:
	rm -f winrespond.exe *.o *.core core *~ respond.res
