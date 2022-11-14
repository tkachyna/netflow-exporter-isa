CC=g++ -std=c++14
CFLAGS=-g -pedantic -Wall -Werror -Wextra
all:
	$(CC) $(CFLAGS) client.cpp arguments.cpp flow.cpp -o flow -LPATH -lpcap
clean:
	rm -rvf *.o flow