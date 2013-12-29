BINS = libuncallutils-impl.so libuncallutils-empty.so libuncallutils.so
LIBS = -lunwind -lunwind-x86_64

all: $(BINS)

libuncallutils-impl.so: uncallutils.o uncall.o
	$(CC) -o $@ -shared $^ $(LIBS)

libuncallutils-empty.so: libuncallutils-empty.o
	$(CC) -o $@ -shared $^ 

libuncallutils.so: libuncallutils-impl.so
	ln -f -s libuncallutils-impl.so $@

.c.o:
	$(CC) -fPIC -c $<

clean:
	rm -rf *~ *.o $(BINS)
	@$(MAKE) -C tools clean
	@$(MAKE) -C tests clean

