#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <map>
#include <unistd.h>
#include <iostream>
#include <string>

#include "dot11.h"

// iwlist mon0 channel
// text recv, channel hopping

struct BeaconInfo {
    int pwr = 0;
    int beacons = 0;
    int data = 0;
};

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

void usage()
{
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump mon0\n");
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void render(std::map<Mac, BeaconInfo>infos) {
    system("clear");
    printf("%-17s\t%7s\n", "BSSID", "Beacons");
    for(std::map<Mac, BeaconInfo>::iterator iter = infos.begin(); iter != infos.end(); ++iter) {
        printf("%-17s\t%7d\n", std::string(iter->first).data(), iter->second.beacons);
    }

}

int main(int argc, char *argv[])
{
    if(!parse(&param, argc, argv)) {
        return -1;
    }

    char errbuf[PCAP_BUF_SIZE];
    pcap_t *handle = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if(handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", param.dev_, errbuf);
        return -1;
    }

    RadiotapHdr *radiotapHdr;
    BeaconHdr *beaconHdr;
    std::map<Mac, BeaconInfo> beaconInfoMap;

    while(true) {
        pcap_pkthdr *packetHdr;
        const u_char* packet;
        int res = pcap_next_ex(handle, &packetHdr, &packet);
        if(res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        radiotapHdr = (RadiotapHdr*)packet;
        packet += radiotapHdr->len_;
        beaconHdr = (BeaconHdr*)packet;

        BeaconInfo beaconInfo;
        if(beaconHdr->typeSubtype() == BeaconHdr::TypeSubtype::Beacon) {
            auto info = beaconInfoMap.find(beaconHdr->addr3_);
            if(info == beaconInfoMap.end()) {
                beaconInfoMap.insert({beaconHdr->addr3_, beaconInfo});
            } 
            beaconInfoMap[beaconHdr->addr3_].beacons++;
        }
        render(beaconInfoMap);
    }

    return 0;
}