CC := gcc
CFLAGS := -I/usr/include/fuse3 -Wall -O2 $(EXTRA_CFLAGS)
LDLIBS := -lfuse3 $(EXTRA_LDLIBS)

all: acfs

clean:
	rm -f acfs

acfs: acfs.c
	$(CC) -std=c99 $(CFLAGS) $(LDLIBS) -o $@ $<
