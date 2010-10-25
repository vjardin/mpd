
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

#ifndef _PDEL_STRUCTS_TYPE_POINTER_H_
#define _PDEL_STRUCTS_TYPE_POINTER_H_

/*********************************************************************
			POINTER TYPES
*********************************************************************/

/*
 * Structs type for a pointer to something.
 */

__BEGIN_DECLS

extern structs_init_t		structs_pointer_init;
extern structs_copy_t		structs_pointer_copy;
extern structs_equal_t		structs_pointer_equal;
extern structs_ascify_t		structs_pointer_ascify;
extern structs_binify_t		structs_pointer_binify;
extern structs_encode_t		structs_pointer_encode;
extern structs_decode_t		structs_pointer_decode;
extern structs_uninit_t		structs_pointer_free;

__END_DECLS

/*
 * Macro arguments:
 *	[const struct structs_type *]	Referent type
 *	[const char *]			Memory allocation type for
 *					    the pointed-to data
 */
#define STRUCTS_POINTER_TYPE(reftype, mtype) {				\
	sizeof(void *),							\
	"pointer",							\
	STRUCTS_TYPE_POINTER,						\
	structs_pointer_init,						\
	structs_pointer_copy,						\
	structs_pointer_equal,						\
	structs_pointer_ascify,						\
	structs_pointer_binify,						\
	structs_pointer_encode,						\
	structs_pointer_decode,						\
	structs_pointer_free,						\
	{ { (void *)(reftype) }, { (void *)(mtype) }, { NULL } }	\
}

#endif	/* _PDEL_STRUCTS_TYPE_POINTER_H_ */

