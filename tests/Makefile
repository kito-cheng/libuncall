BINs = basic_flow

all: $(BINs)

basic_flow: basic_flow.o ../uncall.c
	$(CC) -g -o basic_flow $^ -lunwind -lunwind-x86_64

basic_flow.o: basic_flow.c
	$(CC) -g -c $^

clean:
	rm -rf *~ $(BINs) *.o *.log
