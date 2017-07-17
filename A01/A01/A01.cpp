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
	int ip_version;
	int ip_IHL;
	char ip_TOS[8];
	char ip_length[16];
	char ip_id[16];

	char ip_Xflags[1];
	char ip_Dflags[1];
	char ip_Mflags[1];

	char ip_fOffset[14];
	char ip_TTL[8];
	char ip_protocol[8];
	char ip_checksum[16];
	struct in_addr ip_sip;
	struct in_addr ip_dip;

}ip_header;

typedef struct {
	unsigned short tcp_sport;
	unsigned short tcp_dport;
}tcp_header;

// ---------------- FUNCTIONS ------------------

void print_eth(const unsigned char *data) {
	ether_header *eth;
	eth = (ether_header *) data;

	printf("\n--------------- MAC ADDRESS ---------------\n");
	printf("Destination MAC Address [%02x:%02x:%02x:%02x:%02x:%02x]\n"
	, eth->ether_dmac[0], eth->ether_dmac[1], eth->ether_dmac[2], 
		eth->ether_dmac[3], eth->ether_dmac[4], eth->ether_dmac[5]);
	
	printf("Source MAC Address [%02x:%02x:%02x:%02x:%02x:%02x]\n"
		, eth->ether_smac[0], eth->ether_smac[1], eth->ether_smac[2],
		eth->ether_smac[3], eth->ether_smac[4], eth->ether_smac[5]);
}

void print_ip(const unsigned char *data) {
	ip_header *iph;
}

void print_tcp(const unsigned char *data) {
	tcp_header *tcph;
}

void print_data(const unsigned char *data) {
	printf("---------- DATA ----------");
	printf("%s\n", data);
}

int main(){
	// example : Opening an adapter and capturing the packets
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int count = 0;
	int i = 0;
	int offset = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

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

	/* Open the device */
	if ((adhandle = pcap_open(d->name,          // name of the device
		65536,            // portion of the packet to capture
		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
		1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
	)) == NULL)	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	int res;
	struct pcap_pkthdr *header;
	const unsigned char *pkt_data;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0) continue;
		if (count>10) break;
		count++;
	}

}