#include <queue.h>
#include "skel.h"
//#include "parser.h"

int interfaces[ROUTER_NUM_INTERFACES];
struct route_table_entry *rtable;
int rtable_size;

struct arp_entry *arp_table;

int arp_table_len = 0;

int getFileSize(FILE *f) {
	char c;
	int count = 0;

	for (c = getc(f); c != EOF; c = getc(f))
        if (c == '\n')
            count = count + 1;
	return count;
}

void read_rtable(int N, struct route_table_entry *rtable, FILE *f) {
	char line[100];
	char *token;
	char sourse[16];
	char nextHop[16];
	char mask[16];
	char interface[2];

	for (int i = 0; i < N; i++) {
		fgets(line, sizeof(line), f);
		token = strtok(line, " ");
		int k = 0;
		
		while (token != NULL) {
			k++;
			if (k == 1) {
				strcpy(sourse, token);
				inet_pton(AF_INET, sourse, &rtable[i].prefix);
			}
			if (k == 2) {
				strcpy(nextHop, token);
				inet_pton(AF_INET, nextHop, &rtable[i].next_hop);
			}
			if (k == 3) {
				strcpy(mask, token);
				inet_pton(AF_INET, mask, &rtable[i].mask);
			}
			if (k == 4) {
				strcpy(interface, token);
				rtable[i].interface = atoi(interface);
			}
			token = strtok(NULL, " \n");
	 	}
	}
}
int comparePrefixAndMask(const void *a, const void *b) {
	const struct route_table_entry *first = (struct route_table_entry *)a;
	const struct route_table_entry *second = (struct route_table_entry *)b;
   	if(first->prefix != second->prefix)
	   	return(first->prefix - second->prefix); 
	if(first->prefix == second->prefix) 
		return(first->mask - second->mask);
	return 0;
}
struct route_table_entry *get_best_route(__u32 dest_ip, struct route_table_entry *rtable, int l, int r) {
	if (r >= l) {
		int mid = l + (r - l) / 2;
		if ((rtable[mid].mask & dest_ip) == rtable[mid].prefix) {
		 	return  &rtable[mid];
		}
		if ((rtable[mid].mask & dest_ip) < rtable[mid].prefix)
            return get_best_route(dest_ip, rtable, l, mid - 1);
		
		return	get_best_route(dest_ip,rtable, mid + 1, r);
	}
	return NULL;
}

int main(int argc, char *argv[]) {
	packet m;
	int rc;
	
	init(argc - 2, argv + 2);
	FILE *f;
	f = fopen(argv[1], "r");
	int fileSize = getFileSize(f);

	fseek(f, 0, SEEK_SET);
	rtable = malloc(sizeof(struct route_table_entry) * fileSize + 1);
	arp_table = malloc(sizeof(struct arp_entry) * 20);

	read_rtable(fileSize, rtable, f);
	qsort(rtable, fileSize, sizeof(struct route_table_entry), comparePrefixAndMask);
	queue que = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct arp_header *arp_hdr = parse_arp((struct ether_header *)m.payload);
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		

		if(arp_hdr != NULL) {
			if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {
				if (arp_hdr->tpa == inet_addr(get_interface_ip(m.interface))) {
					get_interface_mac(m.interface, eth_hdr->ether_shost);
					memcpy(eth_hdr->ether_dhost, arp_hdr->sha, sizeof(arp_hdr->sha));
					char *interface_ip_saddr = get_interface_ip(m.interface);	
					uint32_t new_saddr = inet_addr(interface_ip_saddr);
					send_arp(arp_hdr->spa, new_saddr, eth_hdr, m.interface, htons(ARPOP_REPLY));
				}
			} else if(htons(arp_hdr->op) == ARPOP_REPLY) {
				if (queue_empty(que)) continue;
				else {
					packet *newPacket = (packet *)queue_deq(que);
					struct ether_header *GET_eth_hdr = (struct ether_header *)newPacket->payload;
					struct iphdr *GET_ip_hdr = (struct iphdr *)(newPacket->payload + sizeof(struct ether_header));
					struct route_table_entry *entry = get_best_route(GET_ip_hdr->daddr, rtable, 0, fileSize-1);
					get_interface_mac(entry->interface, GET_eth_hdr->ether_shost);
					memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, sizeof(arp_hdr->sha));
					memcpy(GET_eth_hdr->ether_dhost, arp_table[arp_table_len].mac, sizeof(arp_table[arp_table_len].mac));
					arp_table[arp_table_len].ip = GET_ip_hdr->daddr;
					send_packet(entry->interface, newPacket);
					arp_table_len++;
					continue;
				}
			}
		} else {
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
			struct icmphdr *icmp_hdr = parse_icmp(eth_hdr);
			uint32_t interf_ip;
			inet_pton(AF_INET, get_interface_ip(m.interface), &interf_ip);

			if (ip_hdr->daddr == interf_ip) {
				if (icmp_hdr->type == ICMP_ECHO && icmp_hdr != NULL) {
					uint32_t newSourse = ip_hdr->daddr;
					uint32_t newDestination = ip_hdr->saddr;
					send_icmp(newDestination, newSourse, eth_hdr->ether_dhost, eth_hdr->ether_shost, 0, 0, m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
					continue;
				} 
			} else {
				if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) continue;
				
				ip_hdr->ttl--;
				if (ip_hdr->ttl > 0) {
					ip_hdr->check = 0;
					ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
				}

				if (ip_hdr->ttl < 1) {
					uint32_t newSourse = ip_hdr->daddr;
					uint32_t newDestination = ip_hdr->saddr;
					send_icmp_error(newDestination, newSourse, eth_hdr->ether_dhost, eth_hdr->ether_shost, 11, 0, m.interface);
					continue;
				}
				struct route_table_entry *entry = get_best_route(ip_hdr->daddr, rtable, 0, fileSize - 1);
				struct arp_entry *entry_arp = NULL; 
				for(int i = 0; i < arp_table_len ; i++)
					if (entry->next_hop == arp_table[i].ip) {
						entry_arp = &arp_table[i];
						break;
					} 		
				if (entry) {
					if (entry_arp) {	
						memcpy(eth_hdr->ether_dhost, entry_arp->mac, sizeof(entry_arp->mac));
						get_interface_mac(entry->interface, eth_hdr->ether_shost);
						send_packet(entry->interface, &m);
						
					} else {
						packet *new_m = malloc(sizeof(packet));
						memcpy(new_m, &m, sizeof(packet));
						queue_enq(que, new_m);
						eth_hdr->ether_type = htons(ETHERTYPE_ARP);
						hwaddr_aton("ff:ff:ff:ff:ff:ff", eth_hdr->ether_dhost);
						get_interface_mac(entry->interface, eth_hdr->ether_shost);
						inet_pton(AF_INET, get_interface_ip(entry->interface), &interf_ip);
						send_arp(entry->next_hop, interf_ip, eth_hdr, entry->interface, htons(ARPOP_REQUEST));
					}
				} 
				continue;
			} 
		}
	}
}
