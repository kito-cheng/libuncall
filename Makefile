BINS = libuncallutils.so

all: $(BINS)

libuncallutils.so: uncallutils.o uncall.o
	$(CC) -o libuncallutils.so -shared $^

.c.o:
	$(CC) -fPIC -c $<
