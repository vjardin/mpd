
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

#ifndef _PDEL_SYS_LOGFILE_H_
#define _PDEL_SYS_LOGFILE_H_

/*
 * Support for on-disk circular log files. Each file contains the
 * N most recent entries, where an entry is any opaque chunk of
 * data supplied by the application. New entries overwrite the
 * oldest entries in a circular fashion.
 */

struct logfile;

__BEGIN_DECLS

/*
 * Open/create a new logfile.
 *
 * "maxent" sets the maximum number of entries the file can hold.
 * "maxdata" sets the maximum amount of entry data the file can
 * hold.
 *
 * The size of the file will be approx.: maxdata + (8 * maxent) + 20
 *
 * If "path" already exists, it must be a valid logfile and the
 * "maxent" and "maxdata" arguments are ignored.
 *
 * "flags" may be zero, O_SHLOCK or O_EXLOCK.
 *
 * If "path" is NULL, a memory-only logfile is created.
 */
extern struct	logfile *logfile_open(const char *path,
			int flags, u_int32_t maxent, u_int32_t maxdata);

/*
 * Close a logfile.
 */
extern void	logfile_close(struct logfile **lfp);

/*
 * Get the number of valid entries in a logfile.
 */
extern u_int32_t logfile_num_entries(struct logfile *lf);

/*
 * Retrieve a logfile entry.
 *
 * "which" must be a negative number.
 *
 * Entry -1 is the most recent, -2 the second most recent, etc.
 * If "lenp" is not NULL, the length of the entry is returned.
 */
extern const	void *logfile_get(struct logfile *lf, int which, int *lenp);

/*
 * Add an entry.
 */
extern int	logfile_put(struct logfile *lf, const void *data, int len);

/*
 * Trim the number of stored entries.
 */
extern void	logfile_trim(struct logfile *lf, int num);

/*
 * Sync entries to disk.
 */
extern void	logfile_sync(struct logfile *lf);

__END_DECLS

#endif	/* _PDEL_SYS_LOGFILE_H_ */

