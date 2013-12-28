BINS = basic_flow
LIBS = -lunwind -lunwind-x86_64

all: $(BINS)

basic_flow: basic_flow.o ../uncall.c
	$(CC) -g -o basic_flow $^ $(LIBS)

basic_flow.o: basic_flow.c
	$(CC) -g -c $^

clean:
	rm -rf *~ $(BINS) *.o *.log
