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

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphder, uint8_t *pl, int plen)
{
    // [TODO]: Finish TCP checksum calculation
    // printf("tcphder.seq = %u\n",ntohl(tcphder.seq));
    uint32_t sum = 0;
    uint16_t headerlen = tcphder.doff << 2;
    uint16_t len = headerlen+plen;
    sum += (iphdr.saddr >> 16)&0xFFFF;
    sum += (iphdr.saddr)&0xFFFF;
    sum += (iphdr.daddr >> 16)&0xFFFF;
    sum += (iphdr.daddr)&0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(len);
    /* tcp header */
    uint16_t *tcp = (uint16_t *)(void *)&tcphder;
    while(headerlen > 1){
        sum += *tcp;
        tcp++;
        headerlen -=2;
    }
    /* tcp payload */
    tcp = (uint16_t*)pl;
    len = plen;
    while(len > 1){
        sum += *tcp;
        tcp++;
        len -=2;
    }
    if(len > 0){
        sum += ((*tcp)&htons(0xFF00));
    }
    while(sum >> 16){
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    return (unsigned short)sum;
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
    self->thdr.seq = self->thdr.seq + 71; //71 is for "I am client, and I am keeping sending message to server hahahaha";
    // Return payload of TCP
    /* Checksum test */
    // self->thdr.check = 0;
    // self->thdr.check = cal_tcp_cksm(net->ip4hdr,self->thdr,self->pl,71);
    // printf("txp->thdr.check = %x\n",ntohs(self->thdr.check));
    return self->pl;
}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{
    // [TODO]: Fill up self->tcphdr (prepare to send)
    // Sequence Number (calculate before)
    self->thdr.seq = self->x_tx_seq;
    // Acknowledge Number (calculate before)
    self->thdr.ack_seq = self->x_tx_ack;
    // PSH (calculate before)
    self->thdr.psh = self->thdr.psh;
    //payload
    memset(self->pl,0,IP_MAXPACKET * sizeof(uint8_t));
    memcpy(self->pl, data, dlen);
    // Checksum
    self->thdr.check = 0;
    self->thdr.check = cal_tcp_cksm(iphdr,self->thdr,data,dlen);
    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}

