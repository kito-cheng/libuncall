BINS = basic_flow uncallutils-test uncallutils-cxx-test
LIBS = -lunwind -lunwind-x86_64

all: $(BINS)

basic_flow: basic_flow.o ../uncall.c
	$(CC) -g -o basic_flow $^ $(LIBS)

basic_flow.o: basic_flow.c
	$(CC) -g -c $^

uncallutils-test: uncallutils-test.o
	$(CC) -o $@ uncallutils-test.o -luncallutils -L../

uncallutils-cxx-test: uncallutils-cxx-test.o
	$(CXX) -o $@ uncallutils-cxx-test.o -luncallutils -L../

.c.o:
	$(CC) -g -c $^

.cpp.o:
	$(CXX) -g -c $^

clean:
	rm -rf *~ $(BINS) *.o *.log
