#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>
#include <inttypes.h>

#include "esp.h"
#include "transport.h"
#include "hmac.h"

EspHeader esp_hdr_rec;

void get_ik(int type, uint8_t *key)
{
    // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)
    /* build and write SADB_SUMP request */
    /* Wrong code*/
    char buf[4096];
    int s = socket(PF_KEY,SOCK_RAW,PF_KEY_V2);
    struct sadb_msg msg;
    bzero(&msg,sizeof(msg));
    msg.sadb_msg_type = SADB_GET;
    msg.sadb_msg_satype = type;
    msg.sadb_msg_len = sizeof(msg) /8;
    msg.sadb_msg_pid = getpid();
    write(s,&msg,sizeof(msg));
    int goteof = 0;
    while(goteof == 0){
        int msglen;
        struct sadb_msg *msgp;
        msglen = read(s,&buf,sizeof(buf));
        msgp = (struct sadb_msg*) &buf;
        if(msgp->sadb_msg_seq == 0)
            goteof = 1;
    }
    close(s);
}

void get_esp_key(Esp *self)
{
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

uint8_t *set_esp_pad(Esp *self)
{
    // [TODO]: Fiill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)
    return self->pad;
}

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *))
{
    if (!self || !hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;  // Number of bytes to be hashed
    ssize_t ret;

    // [TODO]: Put everything needed to be authenticated into buff and add up nb

    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    self->authlen = ret;
    return self->auth;
}


uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len)
{
    // [TODO]: Collect information from esp_pkt.
    EspHeader *esph = (EspHeader*) esp_pkt;
    self->hdr.spi = ntohl(esph->spi);
    self->hdr.seq = ntohl(esph->seq);
    // printf("self->hdr.spi = %"PRIu32"\n",self->hdr.spi);
    // printf("self->hdr.seq = %"PRIu32"\n",self->hdr.seq);


    // Return payload of ESP
}

Esp *fmt_esp_rep(Esp *self, Proto p)
{
    // [TODO]: Fill up ESP header and trailer (prepare to send)
}

void init_esp(Esp *self)
{
    self->pl = (uint8_t *)malloc(MAXESPPLEN * sizeof(uint8_t));
    self->pad = (uint8_t *)malloc(MAXESPPADLEN * sizeof(uint8_t));
    self->auth = (uint8_t *)malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    self->authlen = HMAC96AUTHLEN;
    self->esp_key = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));

    self->set_padpl = set_esp_pad;
    self->set_auth = set_esp_auth;
    self->get_key = get_esp_key;
    self->dissect = dissect_esp;
    self->fmt_rep = fmt_esp_rep;
}
