
/* eap.h

Copyright (c) 2004, Michael Bretterklieber <michael@bretterklieber.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. The names of the authors may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

This code cannot simply be copied and put under the GNU Public License or
any other GPL-like (LGPL, GPL2) License.

    $Id$
*/


#ifndef _EAP_H_
#define	_EAP_H_

#include "mbuf.h"
#include "timer.h"

/*
 * DEFINITIONS
 */

  #define EAP_NUM_AUTH_PROTOS	2

  enum {
    EAP_REQUEST = 1,
    EAP_RESPONSE,
    EAP_SUCCESS,
    EAP_FAILURE,
  };

  enum {
    EAP_TYPE_IDENT = 1,
    EAP_TYPE_NOTIF,
    EAP_TYPE_NAK,
    EAP_TYPE_MD5CHAL,		/* MD5 Challenge */
    EAP_TYPE_OTP,		/* One Time Password */
    EAP_TYPE_GTC,		/* Generic Token Card */
    EAP_TYPE_RSA_PUB_KEY_AUTH = 9,	/* RSA Public Key Authentication */
    EAP_TYPE_DSS_UNILITERAL,	/* DSS Unilateral */
    EAP_TYPE_KEA,		/* KEA */
    EAP_TYPE_TYPE_KEA_VALIDATE,	/* KEA-VALIDATE */
    EAP_TYPE_EAP_TLS,		/* EAP-TLS RFC 2716 */
    EAP_TYPE_DEFENDER_TOKEN,	/* Defender Token (AXENT) */
    EAP_TYPE_RSA_SECURID,	/* RSA Security SecurID EAP */
    EAP_TYPE_ARCOT,		/* Arcot Systems EAP */
    EAP_TYPE_CISCO_WIRELESS,	/* EAP-Cisco Wireless */
    EAP_TYPE_NOKIA_IP_SC,	/* Nokia IP smart card authentication */
    EAP_TYPE_SRP_SHA1_1,	/* SRP-SHA1 Part 1 */
    EAP_TYPE_SRP_SHA1_2,	/* SRP-SHA1 Part 2 */
    EAP_TYPE_EAP_TTLS,		/* EAP-TTLS */
    EAP_TYPE_RAS,		/* Remote Access Service */
    EAP_TYPE_UMTS,		/* UMTS Authentication and Key Argreement */
    EAP_TYPE_3COM_WIRELESS,	/* EAP-3Com Wireless */
    EAP_TYPE_PEAP,		/* PEAP */
    EAP_TYPE_MS,		/* MS-EAP-Authentication */
    EAP_TYPE_MAKE,		/* MAKE, Mutual Authentication w/Key Exchange */
    EAP_TYPE_CRYPTOCARD,	/* CRYPTOCard */
    EAP_TYPE_MSCHAP_V2,		/* EAP-MSCHAP-V2 */
    EAP_TYPE_DYNAMID,		/* DynamID */
    EAP_TYPE_ROB,		/* Rob EAP */
    EAP_TYPE_SECURID,		/* SecurID EAP */
    EAP_TYPE_MS_AUTH_TLV,	/* MS-Authentication-TLV */
    EAP_TYPE_SENTRINET,		/* SentriNET */
    EAP_TYPE_ACTIONTEC_WIRELESS,/* EAP-Actiontec Wireless */
    EAP_TYPE_COGENT,		/* Cogent Systems Biometrics Authentication EAP */
    EAP_TYPE_AIRFORTRESS,	/* AirFortress EAP */
    EAP_TYPE_HTTP_DIGEST,	/* EAP-HTTP Digest */
    EAP_TYPE_SECURESUITE,	/* SecureSuite EAP */
    EAP_TYPE_DEVICECONNECT,	/* DeviceConnect */
    EAP_TYPE_SPEKE,		/* EAP-SPEKE */
    EAP_TYPE_MOBAC,		/* EAP-MOBAC */
    EAP_TYPE_FAST,		/* EAP-FAST */
  };

  struct eapinfo {
    short		next_id;		/* Packet id */
    short		retry;			/* Resend count */
    struct pppTimer	identTimer;		/* Identity timer */
    u_char		types[EAP_NUM_AUTH_PROTOS];	/* List of requested EAP-Types */
  };
  typedef struct eapinfo	*EapInfo;

/*
 * FUNCTIONS
 */

  extern void	EapStart(EapInfo eap, int which);
  extern void	EapStop(EapInfo eap);
  extern void	EapInput(u_char code, u_char id, const u_char *pkt, u_short len);
  extern const	char *EapCode(u_char code);
  extern const	char *EapType(u_char type);

#endif

