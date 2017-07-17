#include <stdio.h>
#define HAVE_REMOTE
#include "pcap.h"

#pragma comment (lib, "wpcap.lib")  

/* 
	Target
	eth : smac, dmac
	ip : sip, dip
	tcp : sport, dport
	data 
*/

typedef struct {
	
	unsigned char ether_dmac[6];
	unsigned char ether_smac[6];
	unsigned short ether_type;

}ether_header;

typedef struct {

	int ip_ver;
	struct in_addr ip_sip;
	struct in_addr ip_dip;

}ip_header;

typedef struct {
	unsigned short tcp_sport;
	unsigned short tcp_dport;
}tcp_header;

int main() {
	// example : Opening an adapter and capturing the packets
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i = 0;

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next){
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i){
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

}