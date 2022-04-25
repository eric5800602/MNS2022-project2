#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>
#include <inttypes.h>

#include "esp.h"
#include "transport.h"
#include "hmac.h"

EspHeader esp_hdr_rec;

char *get_auth_key(struct sadb_ext *ext)
{
	struct sadb_key *key = (struct sadb_key *)ext;
	int bits;
	unsigned char *p;
	char *auth_key = NULL;
	int len = 0;
	// printf("Authentication key, %d bits: 0x", key->sadb_key_bits);
	for (p = (unsigned char *)(key + 1), bits = key->sadb_key_bits;
		 bits > 0; p++, bits -= 8)
	{
		if (auth_key != NULL)
		{
			char *temp = (char *)malloc(len);
			snprintf(temp, len, "%s", auth_key);
			len += strlen(p);
			auth_key = (char *)malloc(len);
			snprintf(auth_key, len, "%s%02x", temp, *p);
		}
		else
		{
			auth_key = (char *)malloc(sizeof(char) * strlen(p));
			snprintf(auth_key, strlen(p), "%02x", *p);
			len += strlen(p);
		}
		// printf("%02x", *p);
	}
	// printf("\n");
	return strdup(auth_key);
}

unsigned int get_sa_spi(struct sadb_ext *ext)
{
	struct sadb_sa *sa = (struct sadb_sa *)ext;
	return sa->sadb_sa_spi;
}

void get_ik(int type, uint8_t **key)
{
	// [TODO]: Dump authentication key from security association database (SADB)
	// (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)

	char buf[4096];
	int s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	struct sadb_msg msg;
	bzero(&msg, sizeof(msg));
	msg.sadb_msg_version = PF_KEY_V2;
	msg.sadb_msg_type = SADB_DUMP;
	msg.sadb_msg_satype = type;
	msg.sadb_msg_len = sizeof(msg) / 8;
	msg.sadb_msg_pid = getpid();
	write(s, &msg, sizeof(msg));

	while (true)
	{
		int msglen;
		struct sadb_msg *msgp;
		msglen = read(s, &buf, sizeof(buf));
		msgp = (struct sadb_msg *)&buf;
		unsigned int spi = 0;
		char *auth_key = NULL;

		struct sadb_ext *ext;
		msglen -= sizeof(struct sadb_msg);
		ext = (struct sadb_ext *)(msgp + 1);
		while (msglen > 0)
		{
			switch (ext->sadb_ext_type)
			{
			case SADB_EXT_SA:
				spi = ntohl(get_sa_spi(ext));
				break;
			case SADB_EXT_KEY_AUTH:
				auth_key = get_auth_key(ext);
				break;
			}
			msglen -= ext->sadb_ext_len << 3;
			ext = (char *)ext + (ext->sadb_ext_len << 3);
		}
		if (esp_hdr_rec.spi == spi)
		{
			*key = (uint8_t *)malloc(strlen(auth_key));
			memcpy(*key, auth_key, strlen(auth_key));
			printf("spi : %x auth_key : %s key : %s\n", spi, auth_key, *key);
			break;
		}
		if (msgp->sadb_msg_seq == 0)
			break;
	}
	close(s);
}

void get_esp_key(Esp *self)
{
	get_ik(SADB_SATYPE_ESP, &(self->esp_key));
	//printf("esp_key : %s\n", self->esp_key);
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
	if (!self || !hmac)
	{
		fprintf(stderr, "Invalid arguments of %s().\n", __func__);
		return NULL;
	}

	uint8_t buff[BUFSIZE];
	size_t esp_keylen = 16;
	size_t nb = 0; // Number of bytes to be hashed
	ssize_t ret;

	// [TODO]: Put everything needed to be authenticated into buff and add up nb

	ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

	if (ret == -1)
	{
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
    memcpy(&(self->hdr),esph,sizeof(EspHeader));
    //  printf("self->hdr.spi = %"PRIu32"\n",ntohl(self->hdr.spi));
    //  printf("self->hdr.seq = %"PRIu32"\n",ntohl(self->hdr.seq));
    self->pl = esp_pkt + sizeof(EspHeader);
    uint8_t *esp_t = self->pl + sizeof(struct tcphdr);
    // for(int i = 0;esp_t[i] != NULL;i++){
    //     printf("esp_t[%d] = %x\n",i,esp_t[i]);
    // }
    // Return payload of ESP
    return self->pl;
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
