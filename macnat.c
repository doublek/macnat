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

#include <event2/event.h>

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <sys/socket.h>

#include "macnat.h"

#define PROTO_TO_USE ETH_P_ALL

char * random_chars(char *dst, int size);
void print_mac_address(unsigned char *addr);

int client_sock;
int server_sock;

char * random_chars(char *dst, int size)
{
    static const char allowable_chars[] = "1234567890abcdef";
    static const len = 2;
    int i, r;

    for (i=0; i<len; ++i)
    {
        r = (int)((double)rand() / ((double)RAND_MAX + 1) * (sizeof(allowable_chars) -1 ));
        dst[i] = allowable_chars[r];
    }
    dst[i] = '\0';
    return dst;
}

void print_mac_address(unsigned char *addr)
{
    int i;
    printf("%02x", addr[0]);
    for (i=1; i<ETH_ALEN; ++i)
        printf(":%02x", addr[i]);
}

int macnat_create_and_bind_socket(int ifindex, struct sockaddr_ll sdl)
{
    struct packet_mreq mreq;
    int sock;

    int protocol = htons(PROTO_TO_USE);

    if ((sock = socket(PF_PACKET, SOCK_RAW, protocol)) == -1) {
        perror("socket");
        return -1;
    }

    /* Make the interface promisuous */
    mreq.mr_ifindex = ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;

    if (setsockopt(sock, SOL_SOCKET, PACKET_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) == -1) {
        perror("setsockopt");
        return -1;
    }

#if 0
    /* TODO: Nice value for buf. */
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF , NULL, 0) == -1) {
        perror("setsockopt");
        exit(1);
    }
#endif

    if (bind(sock, (struct sockaddr *)&sdl, sizeof(sdl)) == -1) {
        perror("bind");
        return -1;
    }

    return sock;
}

void initialize_server_socket(const char *ifname)
{
    struct sockaddr_ll sdl;
    int ifindex, protocol;

    ifindex = if_nametoindex(ifname);
    protocol = htons(PROTO_TO_USE);

    sdl.sll_family = AF_PACKET;
    sdl.sll_halen = ETH_ALEN;
    //memcpy(sdl.sll_addr, (ether_aton(spoofed_mac_addr))->ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(sdl.sll_addr, (ether_aton("00:0c:29:c6:37:13"))->ether_addr_octet, ETHER_ADDR_LEN);
    sdl.sll_ifindex = ifindex;
    sdl.sll_protocol = protocol; /* Not required for sending */
    sdl.sll_hatype = ARPHRD_ETHER; /* Not required for sending */

    server_sock = macnat_create_and_bind_socket(ifindex, sdl);
    if (server_sock == -1) {
        printf("Error when creating server socket..\n");
        exit(1);
    }
}

void initialize_client_socket(const char *ifname)
{
    struct sockaddr_ll sdl;
    int ifindex, protocol;

    ifindex = if_nametoindex(ifname);
    protocol = htons(PROTO_TO_USE);

    sdl.sll_family = AF_PACKET;
    sdl.sll_protocol = protocol;
    sdl.sll_ifindex = ifindex;
    sdl.sll_hatype = 0; /* Will be filled for us */
    sdl.sll_pkttype = 0; /* Will be filled for us */
    /* sdl.sll_halen and sdl.sll_addr not required for receiveing */

    client_sock = macnat_create_and_bind_socket(ifindex, sdl);

    if (client_sock == -1) {
        printf("Error when creating client socket..\n");
        exit(1);
    }
}

void cleanup_on_exit()
{
    close(server_sock);
    close(client_sock);
}

void replace_with_original_and_send_packet(void *packet, int framelen)
{
    char original_mac_addr[] = "00:0b:5d:8d:6f:c7";

    struct ethhdr *hdr = (struct ethhdr *)packet;

    int protocol = ntohs(hdr->h_proto);

    if (protocol < 0x05DC) {
        printf("INFO: Skipping unknown proto %d %x\n", protocol, hdr->h_proto);
        return;
    }

    print_mac_address(hdr->h_source);
    printf(" --> ");
    print_mac_address(hdr->h_dest);
    printf("\n");

    printf("Replacing with original mac %s and sending packet\n", original_mac_addr);

    /* Construct ethernet header */
    memcpy(hdr->h_dest, (ether_aton(original_mac_addr))->ether_addr_octet, ETH_ALEN);

    if (send(client_sock, packet, framelen, MSG_CONFIRM) == -1) {
        perror("send");
        exit(1);
    }
    printf("Sending Data:\n");
    print_mac_address(hdr->h_source);
    printf(" --> ");
    print_mac_address(hdr->h_dest);
    printf("\n");

}

void modify_and_send_packet(void *packet, int framelen)
{
    const char pattern[] = "00:00:5e";
    char dst1[3], dst2[3], dst3[3];
    char spoofed_mac_addr[18];

    struct ethhdr *hdr = (struct ethhdr *)packet;

    int protocol = ntohs(hdr->h_proto);

    if (protocol < 0x05DC) {
        printf("INFO: Skipping unknown proto %d %x\n", protocol, hdr->h_proto);
        return;
    }
    print_mac_address(hdr->h_source);
    printf(" --> ");
    print_mac_address(hdr->h_dest);
    printf("\n");
    
    sprintf(spoofed_mac_addr, "%s:%s:%s:%s", pattern,
            random_chars(dst1, sizeof(dst1)),
            random_chars(dst2, sizeof(dst2)),
            random_chars(dst3, sizeof(dst3)));

    printf("Modifying and sending packet using MAC: %s\n", spoofed_mac_addr);

    /* Replace ethernet header */
    memcpy(hdr->h_source, (ether_aton(spoofed_mac_addr))->ether_addr_octet, ETH_ALEN);

    if (send(server_sock, packet, framelen, MSG_CONFIRM) == -1) {
        perror("send");
        exit(1);
    }
    printf("Sending Data:\n");
    print_mac_address(hdr->h_source);
    printf(" --> ");
    print_mac_address(hdr->h_dest);
    printf("\n");
}

void read_callback_from_client(evutil_socket_t sock, short what, void *arg)
{
    unsigned char buffer[ETH_FRAME_LEN];
    struct ethhdr *hdr;

    int rv;

    rv = read((int)sock, buffer, ETH_FRAME_LEN);
    if (rv == -1) {
        perror("read");
        exit(1);
    }

    modify_and_send_packet(buffer, rv);
}

void read_callback_from_server(evutil_socket_t sock, short what, void *arg)
{
    unsigned char buffer[ETH_FRAME_LEN];
    struct ethhdr *hdr;

    int rv;

    rv = read((int)sock, buffer, ETH_FRAME_LEN);
    if (rv == -1) {
        perror("read");
        exit(1);
    }

    replace_with_original_and_send_packet(buffer, rv);
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
    const char server_facing_ifname[] = "eth0";
    const char client_facing_ifname[] = "eth1";

    struct event_config *cfg;
    struct event_base *base;

    struct event *client_facing_read, *server_facing_read;

    srand(time(NULL));

    cfg = event_config_new();
    event_config_avoid_method(cfg, "select");

    base = event_base_new_with_config(cfg);
    event_config_free(cfg);
    if (!base) {
        printf("ERROR: could not initialize base event\n");
        exit(1);
    }

    /*
     * We use 2 sockets because we will (probably) receive packets via one
     * interface and send via another interface.
     */
    initialize_server_socket(server_facing_ifname);
    initialize_client_socket(client_facing_ifname);

    /*
     * We not have 2 sockets, one server-facing and one client-facing.
     * Register for appropriate events. For now because of the way the
     * sockets are configured, they are unidirectional. This will change
     * soon.
     * XXX Do not register for write callback, receive_packet will send it out...
     * FIXME Ugly duplicated code for distinguising between client facing and
     * server facing interfaces... Ughhh... I am ashamed... :(
     */
    client_facing_read = event_new(base, client_sock, EV_TIMEOUT|EV_READ|EV_PERSIST,
            read_callback_from_client, (char *)"Client facing reading event");
    server_facing_read = event_new(base, server_sock, EV_TIMEOUT|EV_READ|EV_PERSIST,
            read_callback_from_server, (char *)"Server facing reading event");

    /* Add event and wait forever to event to happen */
    event_add(client_facing_read, NULL);
    event_add(server_facing_read, NULL);

    atexit(cleanup_on_exit);

    /* Enter event loop */
    event_base_dispatch(base);

    return 0;
}
