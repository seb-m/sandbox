CC=gcc
CFLAGS=-W -Wall -O3 -fomit-frame-pointer -funroll-loops
LDFLAGS=
PROG=test

all: $(PROG)

$(PROG): *.c
	$(CC) $(LDFLAGS) -o $@ $(CFLAGS) $(filter %.c,$^)

clean:
	rm -f *.o $(PROG) *~ *#
