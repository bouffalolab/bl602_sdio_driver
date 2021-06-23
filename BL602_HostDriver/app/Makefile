
CC=cc

CFLAGS := -DBUILD_USERSPACE -g

.PHONY: all clean
all: blutl
clean:
	rm -rf blutl

blutl:
	$(CC) -o $@ $(CFLAGS) bl_util.c
