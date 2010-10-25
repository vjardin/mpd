
/*
 * Copyright (c) 2001-2002 Packet Design, LLC.
 * All rights reserved.
 * 
 * Subject to the following obligations and disclaimer of warranty,
 * use and redistribution of this software, in source or object code
 * forms, with or without modifications are expressly permitted by
 * Packet Design; provided, however, that:
 * 
 *    (i)  Any and all reproductions of the source or object code
 *         must include the copyright notice above and the following
 *         disclaimer of warranties; and
 *    (ii) No rights are granted, in any manner or form, to use
 *         Packet Design trademarks, including the mark "PACKET DESIGN"
 *         on advertising, endorsements, or otherwise except as such
 *         appears in the above copyright notice or in the software.
 * 
 * THIS SOFTWARE IS BEING PROVIDED BY PACKET DESIGN "AS IS", AND
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, PACKET DESIGN MAKES NO
 * REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, REGARDING
 * THIS SOFTWARE, INCLUDING WITHOUT LIMITATION, ANY AND ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
 * OR NON-INFRINGEMENT.  PACKET DESIGN DOES NOT WARRANT, GUARANTEE,
 * OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF, OR THE RESULTS
 * OF THE USE OF THIS SOFTWARE IN TERMS OF ITS CORRECTNESS, ACCURACY,
 * RELIABILITY OR OTHERWISE.  IN NO EVENT SHALL PACKET DESIGN BE
 * LIABLE FOR ANY DAMAGES RESULTING FROM OR ARISING OUT OF ANY USE
 * OF THIS SOFTWARE, INCLUDING WITHOUT LIMITATION, ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, PUNITIVE, OR CONSEQUENTIAL
 * DAMAGES, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES, LOSS OF
 * USE, DATA OR PROFITS, HOWEVER CAUSED AND UNDER ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF PACKET DESIGN IS ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Archie Cobbs <archie@freebsd.org>
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include "structs/structs.h"
#include "structs/type/array.h"
#include "structs/type/ip4.h"
#include "util/typed_mem.h"

/*********************************************************************
			IPv4 ADDRESS TYPE
*********************************************************************/

static structs_ascify_t		structs_ip4_ascify;
static structs_binify_t		structs_ip4_binify;

static char *
structs_ip4_ascify(const struct structs_type *type,
	const char *mtype, const void *data)
{
	const u_char *const bytes
	    = (const u_char *)&((const struct in_addr *)data)->s_addr;
	char buf[16];

	/* Don't use inet_ntoa(), it's not thread safe */
	snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
	    bytes[0], bytes[1], bytes[2], bytes[3]);
	return (STRDUP(mtype, buf));
}

static int
structs_ip4_binify(const struct structs_type *type,
	const char *ascii, void *data, char *ebuf, size_t emax)
{
	char buf[32];
	char *s;
	char *t;
	int val;
	int i;

	/* Trim whitespace */
	while (isspace(*ascii))
		ascii++;
	strlcpy(buf, ascii, sizeof(buf));
	for (i = strlen(buf); i > 0 && isspace(buf[i - 1]); i--);
	buf[i] = '\0';

	/* Parse each byte */
	for (s = buf, i = 0; i < 4; s = t, i++) {
		for (t = s; isdigit(*t); t++);
		if (*t != ((i < 3) ? '.' : '\0'))
			goto bogus;
		if (t - s < 1 || t - s > 3)
			goto bogus;
		*t++ = '\0';
		if ((val = atoi(s)) > 255)
			goto bogus;
		((u_char *)data)[i] = (u_char)val;
	}

	/* OK */
	return (0);

bogus:
	strlcpy(ebuf, "invalid IP address", emax);
	errno = EINVAL;
	return (-1);
}

const struct structs_type structs_type_ip4 = {
	sizeof(struct in_addr),
	"ip4",
	STRUCTS_TYPE_PRIMITIVE,
	structs_region_init,
	structs_region_copy,
	structs_region_equal,
	structs_ip4_ascify,
	structs_ip4_binify,
	structs_region_encode,
	structs_region_decode,
	structs_nothing_free,
};

