/*
 * A simple tool to re-write the MAC address of packets that go through this
 * daemon. Maintains a dictionary that contains a mapping of the source ip
 * address of a packet to a randomize mac address and rewrites the source
 * mac address of the packet for outgoing (egress?) packets. Does the reverse
 * for incoming (ingress?) packets.
 *
 * EXAMPLE: 
 *   Egress (all source):
 * 	<00:30:1b:b9:97:d7>/192.168.10.3 --> <00:00:5e:00:04:44>/192.168.10.3
 * 	<00:30:1b:b9:97:d7>/192.168.10.4 --> <00:00:5e:00:01:44>/192.168.10.4
 * 	<00:30:1b:b9:97:d7>/192.168.10.5 --> <00:00:5e:00:01:44>/192.168.10.4
 *
 *   Ingress (all destination):
 *	<00:00:5e:00:04:44>/192.168.10.3 --> <00:30:1b:b9:97:d7>/192.168.10.3
 *	<00:00:5e:00:01:44>/192.168.10.4 --> <00:30:1b:b9:97:d7>/192.168.10.4
 * 	<00:00:5e:00:01:44>/192.168.10.4 --> <00:30:1b:b9:97:d7>/192.168.10.5
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <net/ethernet.h>
#include <net/if_arp.h> /* Sigh it is now Linux only */
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h> /* Sigh it is now Linux only */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <sys/socket.h>

char * random_chars(char *dst, int size)
{
    static const char allowable_chars[] = "1234567890abcdef";
    static const len = 2;
    int i, r;

    for(i=0; i<len; ++i)
    {
        r = (int)((double)rand() / ((double)RAND_MAX + 1) * (sizeof(allowable_chars) -1 ));
        dst[i] = allowable_chars[r];
    }
    dst[i] = '\0';
    return dst;
}

void modify_and_send_packet(void *packet)
{
    const char pattern[] = "00:00:5e";
    char dst1[3], dst2[3], dst3[3];
    char spoofed_mac_addr[18];

    struct sockaddr_ll sdl;
    struct packet_mreq mreq;
    int send_sock, ifindex, protocol;

    /* FIXME: Hardcoded... Sigh.... */
    ifindex = if_nametoindex("eth2");
    protocol = htons(ETH_P_ALL);

    sdl.sll_family = AF_PACKET;
    sdl.sll_halen = 6; /* FIXME: Magic number */
    memcpy(sdl.sll_addr, (ether_aton(spoofed_mac_addr))->ether_addr_octet, ETHER_ADDR_LEN);
    sdl.sll_ifindex = ifindex;
    sdl.sll_protocol = 0; /* Not required for sending */
    sdl.sll_hatype = 0; /* Not required for sending */
    sdl.sll_pkttype = 0; /* Not required for sending */

    /*
     * We use 2 sockets because we will (probably) receive packets via one
     * interface and send via another interface.
     */
    if((send_sock = socket(PF_PACKET, SOCK_RAW, protocol)) == -1) {
        perror("socket");
        exit(1);
    }

    mreq.mr_ifindex = ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;

    if(setsockopt(send_sock, SOL_SOCKET, PACKET_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) == -1) {
        perror("setsockopt");
        exit(1);
    }

    sprintf(spoofed_mac_addr, "%s:%s:%s:%s", pattern,
            random_chars(dst1, sizeof(dst1)),
            random_chars(dst2, sizeof(dst2)),
            random_chars(dst3, sizeof(dst3)));

    printf("Should modify and send packet using MAC: %s... \n"
            "Doing nothing for now...\n", spoofed_mac_addr);
}

void print_mac_address(unsigned char *addr)
{
    int i;
    printf("%02x", addr[0]);
    for(i=1; i<ETH_ALEN; ++i)
        printf(":%02x", addr[i]);
}

void receive_packet()
{
    struct sockaddr_ll sdl;
    struct packet_mreq mreq;
    int recv_sock, ifindex, protocol;

    unsigned char buffer[ETH_FRAME_LEN];
    struct ethhdr *hdr;

    /* FIXME: Hardcoded... Sigh...*/
    ifindex = if_nametoindex("eth2");
    protocol = htons(ETH_P_ALL);

    sdl.sll_family = AF_PACKET;
    sdl.sll_protocol = protocol;
    sdl.sll_ifindex = ifindex;
    sdl.sll_hatype = 0; /* Will be filled for us */
    sdl.sll_pkttype = 0; /* Will be filled for us */
    /* sdl.sll_halen and sdl.sll_addr not required for receiveing */

    if((recv_sock = socket(PF_PACKET, SOCK_RAW, protocol)) == -1) {
        perror("socket");
        exit(1);
    }

    mreq.mr_ifindex = ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;

    if(setsockopt(recv_sock, SOL_SOCKET, PACKET_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) == -1) {
        perror("setsockopt");
        exit(1);
    }

#if 0
    /* TODO: Nice value for buf. */
    if(setsockopt(recv_sock, SOL_SOCKET, SO_RCVBUF , NULL, 0) == -1) {
        perror("setsockopt");
        exit(1);
    }
#endif

    if(bind(recv_sock, (struct sockaddr *)&sdl, sizeof(sdl)) == -1) {
        perror("bind");
        exit(1);
    }

    while (1) {
        if (read(recv_sock, buffer, ETH_FRAME_LEN) == -1) {
            perror("read");
            exit(1);
        }

        printf("Got Data:\n");
        hdr = (struct ethhdr *)buffer;
        print_mac_address(hdr->h_source);
        printf(" --> ");
        print_mac_address(hdr->h_dest);
        printf("\n");
        modify_and_send_packet(buffer);
    }
}

void usage()
{
    printf("Usage: macnat <xx:yy:zz>\n"
            "where:\n"
            "  xx:yy:zz will be used to generate mac addresses like so:"
            "  xx:yy:zz:00:01:ab\n"
            "  xx:yy:zz:01:0f:12\n");
}

int main(int argc, char *argv[])
{
    srand(time(NULL));

    /* TODO: Event based code goes here.
     *  Things I have thought of for now include:
     *      1. Sock read.
     *      2. Sock write.
     * Until then just call receive_packet which does an infinite loop. :-|
     */
    receive_packet();

    return 0;
}
