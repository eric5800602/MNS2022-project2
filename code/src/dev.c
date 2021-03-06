#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <errno.h>

#include "dev.h"
#include "net.h"
#include "esp.h"
#include "replay.h"
#include "transport.h"
extern int errno;
inline static int get_ifr_mtu(struct ifreq *ifr)
{
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    if (ioctl(fd, SIOCGIFMTU, ifr) < 0) {
        perror("ioctl()");
        close(fd);
        exit(EXIT_FAILURE);
    }

    return ifr->ifr_mtu;
}

inline static struct sockaddr_ll init_addr(char *name)
{
    struct sockaddr_ll addr;
    bzero(&addr, sizeof(addr));
    /*
    unsigned short	sll_family;
	__be16		sll_protocol;
	int		sll_ifindex;
	unsigned short	sll_hatype;
	unsigned char	sll_pkttype;
	unsigned char	sll_halen;
	unsigned char	sll_addr[8];
    */
    // [TODO]: Fill up struct sockaddr_ll addr which will be used to bind in func set_sock_fd
    // Change dev name to sll_index
    struct ifreq ifr;
    memset(&ifr,0,sizeof(ifr));
    int s;
    s = socket(AF_INET,SOCK_DGRAM,0);
    memcpy(ifr.ifr_name,name,strlen(name));
    int err = ioctl(s,SIOCGIFINDEX,&ifr);
    if(!err){
        addr.sll_ifindex = ifr.ifr_ifindex;
    }
    else{
        printf("ioctl:%s\n",strerror(errno));
    }
    err = ioctl(s,SIOCGIFHWADDR,&ifr);
    if(!err){
        addr.sll_addr[0] = ifr.ifr_ifru.ifru_hwaddr.sa_data[0];
        addr.sll_addr[1] = ifr.ifr_ifru.ifru_hwaddr.sa_data[1];
        addr.sll_addr[2] = ifr.ifr_ifru.ifru_hwaddr.sa_data[2];
        addr.sll_addr[3] = ifr.ifr_ifru.ifru_hwaddr.sa_data[3];
        addr.sll_addr[4] = ifr.ifr_ifru.ifru_hwaddr.sa_data[4];
        addr.sll_addr[5] = ifr.ifr_ifru.ifru_hwaddr.sa_data[5];
    }
    else{
        printf("ioctl:%s\n",strerror(errno));
    }
    close(s);
    addr.sll_family = AF_PACKET;
    addr.sll_halen = ETH_ALEN;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_pkttype = PACKET_OUTGOING;


    if (addr.sll_ifindex == 0) {
        perror("if_nameindex()");
        exit(EXIT_FAILURE);
    }

    return addr;
}

inline static int set_sock_fd(struct sockaddr_ll dev)
{
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    bind(fd, (struct sockaddr *)&dev, sizeof(dev));

    return fd;
}
void fmt_frame(Dev *self, Net net, Esp esp, Txp txp)
{
    // [TODO]: store the whole frame into self->frame
    // and store the length of the frame into self->framelen
    self->framelen = LINKHDRLEN;
    // copy ipv4 header to frame
    memcpy(self->frame + self->framelen, &net.ip4hdr, net.hdrlen);
    self->framelen += net.hdrlen;
    // copy esp header to frame
    memcpy(self->frame + self->framelen, &esp.hdr, sizeof(EspHeader));
    self->framelen += sizeof(EspHeader);
    // copy esp payload(encrypted txp pl) to frame
    memcpy(self->frame + self->framelen, esp.pl, txp.hdrlen+txp.plen);
    //printf("txp.pl = %s",(char*)(esp.pl+txp.hdrlen));
    self->framelen = self->framelen + txp.hdrlen + txp.plen;
    // copy padding
    memcpy(self->frame + self->framelen, esp.pad , esp.tlr.pad_len);
    self->framelen += esp.tlr.pad_len;
    // copy esp trailer
    memcpy(self->frame + self->framelen, &esp.tlr , sizeof(EspTrailer));
    self->framelen += sizeof(EspTrailer);
    // copy esp au data
    memcpy(self->frame + self->framelen, esp.auth , esp.authlen);
    self->framelen += esp.authlen;
    //length of the frame is in self->framelen
    /* Debug */
    // memcpy(self->frame + self->framelen, &net.ip4hdr, net.hdrlen);
    // self->framelen += net.hdrlen;
    // memcpy(self->frame + self->framelen, esp.pl, txp.hdrlen+txp.plen);
    // self->framelen = self->framelen + txp.hdrlen + txp.plen;
}

ssize_t tx_frame(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);
    nb = sendto(self->fd, self->frame, self->framelen,
                0, (struct sockaddr *)&self->addr, addrlen);
    if (nb <= 0) perror("sendto()");

    return nb;
}

ssize_t rx_frame(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);

    nb = recvfrom(self->fd, self->frame, self->mtu,
                  0, (struct sockaddr *)&self->addr, &addrlen);
    if (nb <= 0)
        perror("recvfrom()");

    return nb;
}

void init_dev(Dev *self, char *dev_name)
{
    if (!self || !dev_name || strlen(dev_name) + 1 > IFNAMSIZ) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);

    self->mtu = get_ifr_mtu(&ifr);

    self->addr = init_addr(dev_name);
    self->fd = set_sock_fd(self->addr);

    self->frame = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));
    self->framelen = 0;

    self->fmt_frame = fmt_frame;
    self->tx_frame = tx_frame;
    self->rx_frame = rx_frame;

    self->linkhdr = (uint8_t *)malloc(LINKHDRLEN);
}
