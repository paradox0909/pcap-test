#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#define ETHER_ADDR_LEN 6


struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */   
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

void print_MAC(u_int8_t* pac){
	
	printf("%02x:%02x:%02x:%02x:%02x:%02x:",pac[0],pac[1],pac[2],pac[3],pac[4],pac[5]);
}




void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		struct libnet_ethernet_hdr *ether_hdr=(struct libnet_ethernet_hdr *)packet;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		print_MAC(ether_hdr->ether_dhost);
		print_MAC(ether_hdr->ether_shost);		
		

		printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}
