# ===================================================================================
 # 
 #  ISA Project - Implementation of NetFlow exporer
 #  @author Tadeas Kachyna <xkachy00@fit.vutbr.cz>
 #  @date 14.11.2022
 #  @file Makefile

 # ====================================================================================

CC=g++ -std=c++14
CFLAGS=-g -pedantic -Wall -Werror -Wextra
all:
	$(CC) $(CFLAGS) client.cpp arguments.cpp flow.cpp -o flow -lpcap
clean:
	rm -rvf *.o flow