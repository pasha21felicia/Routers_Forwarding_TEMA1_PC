#pragma once
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

typedef uint32_t in_addr_t;
struct route_table_entry {
	uint32_t prefix; //struct in_addr 
	uint32_t next_hop;
 	uint32_t mask;
	int interface;
} __attribute__((packed));

void read_rtable(int N, struct route_table_entry *rtable, FILE *f);
