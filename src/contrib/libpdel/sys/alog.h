
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

#ifndef _PDEL_SYS_ALOG_H_
#define _PDEL_SYS_ALOG_H_

#include <sys/types.h>
#include <sys/time.h>

#include <stdarg.h>
#include <regex.h>

#ifndef __FreeBSD__
#define __printflike(x,y)
#endif

/*
 * Simple support for logging channels. Each channel can log to
 * standard error, local syslog, or remote syslog, and has a minimum
 * log severity filter.
 */

#define ALOG_MAX_CHANNELS	16	/* max number of channels */

/*
 * This structure is used to configure a channel.
 */
struct alog_config {
	const char	*path;		/* logfile filename, or NULL for none */
	const char	*name;		/* syslog id, or null to disable */
	const char	*facility;	/* syslog facility, null for stderr */
	struct in_addr	remote_server;	/* remote server, or 0.0.0.0 local */
	int		min_severity;	/* min severity to actually log */
	int		histlen;	/* how many history entries to save */
};

/* Entries in the log history are returned in this form */
struct alog_entry {
	time_t	when;			/* when event was logged */
	int	sev;			/* entry log severity */
	char	msg[0];			/* entry contents (including NUL) */
};

DEFINE_STRUCTS_ARRAY(alog_history, struct alog_entry *);

__BEGIN_DECLS

/*
 * Initialize or reconfigure a logging channel.
 *
 *	channel		Between zero and ALOG_MAX_CHANNELS - 1.
 *	conf		Channel configuration.
 */
extern int	alog_configure(int channel, const struct alog_config *conf);

/*
 * Reset a logging channel.
 */
extern int	alog_shutdown(int channel);

/*
 * Set current logging channel.
 */
extern int	alog_set_channel(int channel);

/*
 * Enable/disable debugging on a channel. Everything logged to the
 * channel will be logged to stderr as well.
 */
extern void	alog_set_debug(int channel, int enabled);

/*
 * Get a selection from the log history.
 *
 * The caller's structs array is filled in and is an array of
 * pointers to struct alog_entry.
 *
 * Caller should free the returned array by calling
 * "structs_free(&alog_history_type, NULL, list)".
 */
extern int	alog_get_history(int channel, int min_severity,
			int max_entries, time_t max_age,
			const regex_t *preg, struct alog_history *list);

/*
 * Clear (i.e., forget) log history.
 */
extern int	alog_clear_history(int channel);

/*
 * Log to the currently active logging channel. Preserves errno.
 */
extern void	alog(int sev, const char *fmt, ...) __printflike(2, 3);
extern void	valog(int sev, const char *fmt,
			va_list args) __printflike(2, 0);

/*
 * Convert between numeric syslog facility and string.
 */
extern int	alog_facility(const char *name);
const char	*alog_facility_name(int facility);

/*
 * Convert between numeric syslog severity and string.
 */
extern int	alog_severity(const char *name);
const char	*alog_severity_name(int sev);

/*
 * Expand '%m' in a format string.
 *
 * Returns a pointer to a static buffer.
 */
extern void	alog_expand(const char *fmt,
			int errnum, char *buf, size_t bufsize);

/* Some useful alog "structs" types */
extern const struct structs_type	alog_facility_type;
extern const struct structs_type	alog_severity_type;
extern const struct structs_type	alog_config_type;
extern const struct structs_type	alog_history_type;

__END_DECLS

/* Handy macro for a common usage */
#ifdef __GNUC__
#define alogf(sev, fmt, arg...)	alog(sev, "%s: " fmt, __FUNCTION__ , ## arg)
#else
#define alogf			alog
#endif

#endif	/* _PDEL_SYS_ALOG_H_ */
