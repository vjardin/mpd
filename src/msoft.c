
/*
 * msoft.c
 *
 * Rewritten by Archie Cobbs <archie@freebsd.org>
 * Copyright (c) 1998-1999 Whistle Communications, Inc. All rights reserved.
 * See ``COPYRIGHT.whistle''
 */

#include "ppp.h"
#include "msoft.h"
#ifdef ENCRYPTION_MPPE
#include "sha-1.h"
#endif
#include <md4.h>
#include <des.h>

/*
 * This stuff is described in:
 *	ftp://ietf.org/internet-drafts/draft-ietf-pppext-mschap-00.txt
 *	ftp://ietf.org/internet-drafts/draft-ietf-pppext-mppe-00.txt
 */

/*
 * INTERNAL FUNCTIONS
 */

  static void	ChallengeResponse(const u_char *chal,
			const char *pwHash, u_char *hash);
  static void	DesEncrypt(const u_char *clear, u_char *key0, u_char *cypher);
  static void	ChallengeHash(const u_char *peerchal, const u_char *authchal,
			const char *username, u_char *hash);

/*
 * LMPasswordHash()
 *
 * password	ASCII password
 * hash		16 byte output LanManager hash
 */

void
LMPasswordHash(const char *password, u_char *hash)
{
  const char	*const clear = "KGS!@#$%%";
  u_char	up[14];		/* upper case password */
  int		k;

  memset(&up, 0, sizeof(up));
  for (k = 0; k < sizeof(up) && password[k]; k++)
    up[k] = toupper(password[k]);

  DesEncrypt(clear, &up[0], &hash[0]);
  DesEncrypt(clear, &up[7], &hash[8]);
}

/*
 * NTPasswordHash()
 *
 * password	ASCII (NOT Unicode) password
 * hash		16 byte output NT hash
 */

void
NTPasswordHash(const char *password, u_char *hash)
{
  u_int16_t	unipw[128];
  int		unipwLen;
  MD4_CTX	md4ctx;
  const char	*s;

/* Convert password to Unicode */

  for (unipwLen = 0, s = password; unipwLen < sizeof(unipw) / 2 && *s; s++)
    unipw[unipwLen++] = htons(*s << 8);

/* Compute MD4 of Unicode password */

  MD4Init(&md4ctx);
  MD4Update(&md4ctx, (u_char *) unipw, unipwLen * sizeof(*unipw));
  MD4Final(hash, &md4ctx);
}

/*
 * NTChallengeResponse()
 *
 * chal		8 byte challenge
 * password	ASCII (NOT Unicode) password
 * hash		24 byte response
 */

void
NTChallengeResponse(const u_char *chal, const char *password, u_char *hash)
{
  u_char	pwHash[16];

  NTPasswordHash(password, pwHash);
  ChallengeResponse(chal, pwHash, hash);
}

/*
 * ChallengeResponse()
 *
 * chal		8 byte challenge
 * pwHash	16 byte password hash
 * hash		24 byte response
 */

static void
ChallengeResponse(const u_char *chal, const char *pwHash, u_char *hash)
{
  u_char	buf[21];
  int		k;

  memset(&buf, 0, sizeof(buf));
  memcpy(buf, pwHash, 16);

/* Use DES to hash the hash */

  for (k = 0; k < 3; k++)
  {
    u_char	*const key = &buf[k * 7];
    u_char	*const output = &hash[k * 8];

    DesEncrypt(chal, key, output);
  }
}

/*
 * DesEncrypt()
 *
 * clear	8 byte cleartext
 * key		7 byte key
 * cypher	8 byte cyphertext
 */

static void
DesEncrypt(const u_char *clear, u_char *key0, u_char *cypher)
{
  des_key_schedule	ks;
  u_char		key[8];

/* Create DES key */

  key[0] = key0[0] & 0xfe;
  key[1] = (key0[0] << 7) | (key0[1] >> 1);
  key[2] = (key0[1] << 6) | (key0[2] >> 2);
  key[3] = (key0[2] << 5) | (key0[3] >> 3);
  key[4] = (key0[3] << 4) | (key0[4] >> 4);
  key[5] = (key0[4] << 3) | (key0[5] >> 5);
  key[6] = (key0[5] << 2) | (key0[6] >> 6);
  key[7] = key0[6] << 1;
  des_set_key((des_cblock *) key, ks);

/* Encrypt using key */

  des_ecb_encrypt((des_cblock *) clear, (des_cblock *) cypher, ks, 1);
}

#ifdef ENCRYPTION_MPPE

/*
 * MsoftGetStartKey()
 */

void
MsoftGetStartKey(u_char *chal, u_char *h)
{
  SHA1_CTX	c;
  u_char	hash[20];

  SHA1Init(&c);
  SHA1Update(&c, h, 16);
  SHA1Update(&c, h, 16);
  SHA1Update(&c, chal, 8);
  SHA1Final(hash, &c);
  memcpy(h, hash, 16);
}

#endif

/*
 * GenerateNTResponse()
 *
 * authchal	16 byte authenticator challenge
 * peerchal	16 byte peer challenge
 * username	ASCII username
 * password	ASCII (NOT Unicode) password
 * hash		24 byte response
 */

void
GenerateNTResponse(const u_char *authchal, const u_char *peerchal,
  const char *username, const char *password, u_char *hash)
{
  u_char	chal[8];
  u_char	pwHash[16];

  ChallengeHash(peerchal, authchal, username, chal);
  NTPasswordHash(password, pwHash);
  ChallengeResponse(chal, pwHash, hash);
}

/*
 * ChallengeHash()
 *
 * peerchal	16 byte peer challenge
 * authchal	16 byte authenticator challenge
 * username	ASCII username
 * hash		8 byte response
 */

static void
ChallengeHash(const u_char *peerchal, const u_char *authchal,
  const char *username, u_char *hash)
{
  SHA1_CTX	c;
  u_char	digest[20];

  SHA1Init(&c);
  SHA1Update(&c, peerchal, 16);
  SHA1Update(&c, authchal, 16);
  SHA1Update(&c, username, strlen(username));
  SHA1Final(digest, &c);
  memcpy(hash, digest, 8);
}

#ifdef ENCRYPTION_MPPE

/*
 * MsoftGetMasterKey()
 */

void
MsoftGetMasterKey(u_char *resp, u_char *h)
{
  SHA1_CTX	c;
  u_char	hash[20];
  static char Magic1[] = "This is the MPPE Master Key";

  SHA1Init(&c);
  SHA1Update(&c, h, 16);
  SHA1Update(&c, resp, 24);
  SHA1Update(&c, Magic1, sizeof(Magic1) - 1);
  SHA1Final(hash, &c);
  memcpy(h, hash, 16);
}

/*
 * MsoftGetAsymetricStartKey()
 */

void
MsoftGetAsymetricStartKey(u_char *h, int xmit)
{
  SHA1_CTX		c;
  u_char		hash[20];
  static const char	Magic2[] =
    "On the client side, this is the send key;"
    " on the server side, it is the receive key.";
  static const char	Magic3[] =
    "On the client side, this is the receive key;"
    " on the server side, it is the send key.";

  /* pads used in key derivation - from sha1dgst.c */
  static const u_char SHApad1[40] =
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  static const u_char SHApad2[40] =
    {0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
     0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
     0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
     0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2};

  SHA1Init(&c);
  SHA1Update(&c, h, 16);
  SHA1Update(&c, SHApad1, 40);
  SHA1Update(&c, xmit ? Magic2 : Magic3, 84);
  SHA1Update(&c, SHApad2, 40);
  SHA1Final(hash, &c);
  memcpy(h, hash, 16);
}

#endif
