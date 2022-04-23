#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "net.h"
#include "transport.h"
#include "esp.h"

uint16_t cal_ipv4_cksm(struct iphdr iphdr)
{
    // [TODO]: Finish IP checksum calculation
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len)
{
    // [TODO]: Collect information from pkt.
    /* Get Source and Dst IP */
    sprintf(self->src_ip,"%d.%d.%d.%d\n",(unsigned char)(pkt[12]),(unsigned char)(pkt[13]),(unsigned char)(pkt[14]),(unsigned char)(pkt[15]));
    sprintf(self->dst_ip,"%d.%d.%d.%d\n",(unsigned char)(pkt[16]),(unsigned char)(pkt[17]),(unsigned char)(pkt[18]),(unsigned char)(pkt[19]));
    // printf("Soure = %s\n",self->src_ip);
    // printf("Dst = %s\n",self->dst_ip);
    
    struct ip *iph = (struct ip*) pkt;
    memcpy(&(self->ip4hdr),iph,sizeof(struct ip));
    //printf("ip_hl = %u\n",(iph->ip_hl)*4);
    //store as bytes
    self->hdrlen = (size_t)(iph->ip_hl)*4;

    /* calculate payload length */
    self->plen = ntohs(iph->ip_len) - self->hdrlen;
    //printf("self->plen = %u\n",self->plen);

    /* Check the protocol */
    self->pro = iph->ip_p;
    //printf("0x%x\n",iph->ip_p);

    // Return payload of network layer
    /* Return the pkt + ipv4 header length */
    return pkt + self->hdrlen;
}

Net *fmt_net_rep(Net *self)
{
    // [TODO]: Fill up self->ip4hdr (prepare to send)

    return self;
}

void init_net(Net *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    self->src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->hdrlen = sizeof(struct iphdr);

    self->dissect = dissect_ip;
    self->fmt_rep = fmt_net_rep;
}
