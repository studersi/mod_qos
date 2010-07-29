
CFLAGS=

all: qslog qsrotate qscheck qspng

BASE_OBJECTS = qs_util.o

qs_util.o: qs_util.c qs_util.h
	cc $(CFLAGS) -c -I. qs_util.c

qslog: qslog.c $(BASE_OBJECTS)
	cc $(CFLAGS) -I. $(BASE_OBJECTS) -o qslog qslog.c -lpthread
	strip qslog

qsrotate: qsrotate.c $(BASE_OBJECTS)
	cc $(CFLAGS) -I. $(BASE_OBJECTS) -o qsrotate qsrotate.c -lpthread -lz
	strip qsrotate

qscheck: qscheck.c $(BASE_OBJECTS)
	cc $(CFLAGS) -I. $(BASE_OBJECTS) -o qscheck qscheck.c
	strip qscheck

qspng: qspng.c $(BASE_OBJECTS)
	cc $(CFLAGS) -I. -I../libpng $(BASE_OBJECTS) -o qspng qspng.c -L../libpng/.libs -lpng14 -lz
	strip qspng

clean:
	rm -f *.o qslog qstotate qscheck qspng
