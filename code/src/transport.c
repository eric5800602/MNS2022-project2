#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net.h"
#include "transport.h"

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
{
    // [TODO]: Finish TCP checksum calculation
}

uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len)
{
    // [TODO]: Collect information from segm
    struct tcphdr *tcph = (struct tcphdr*)segm;
    self->x_src_port = tcph->th_sport;
    self->x_dst_port = tcph->th_dport;
    memcpy(&(self->thdr),tcph,sizeof(struct tcphdr));
    // (Check IP addr & port to determine the next seq and ack value)
    //store as byte
    self->hdrlen = (uint8_t)tcph->doff *4;
    /* I don't know how to calculate plen */
    self->plen = segm_len;
    //printf("%d\n",self->hdrlen);
    //printf("src = %d\n",ntohs(self->x_src_port));
    //printf("dst = %d\n",ntohs(self->x_dst_port));
    self->pl = segm + self->hdrlen;
    // Return payload of TCP
    return self->pl;
}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{
    // [TODO]: Fill up self->tcphdr (prepare to send)

    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}

