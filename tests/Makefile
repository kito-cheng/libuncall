BINS = basic_flow uncallutils-test libuncallutils.so
LIBS = -lunwind -lunwind-x86_64

all: $(BINS)

basic_flow: basic_flow.o ../uncall.c
	$(CC) -g -o basic_flow $^ $(LIBS)

basic_flow.o: basic_flow.c
	$(CC) -g -c $^

uncallutils-test: uncallutils-test.o
	$(CC) -o $@ uncallutils-test.o -luncallutils -L../

libuncallutils.so: ../libuncallutils-empty.so
	ln -f -s ../libuncallutils-empty.so $@

.c.o:
	$(CC) -g -c $^

clean:
	rm -rf *~ $(BINS) *.o *.log
