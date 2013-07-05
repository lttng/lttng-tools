/*
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include "compiler.h"
#include "ust-endian.h"

/*
 * Hash function
 * Source: http://burtleburtle.net/bob/c/lookup3.c
 * Originally Public Domain
 */

#define rot(x, k) (((x) << (k)) | ((x) >> (32 - (k))))

#define mix(a, b, c) \
do { \
	a -= c; a ^= rot(c,  4); c += b; \
	b -= a; b ^= rot(a,  6); a += c; \
	c -= b; c ^= rot(b,  8); b += a; \
	a -= c; a ^= rot(c, 16); c += b; \
	b -= a; b ^= rot(a, 19); a += c; \
	c -= b; c ^= rot(b,  4); b += a; \
} while (0)

#define final(a, b, c) \
{ \
	c ^= b; c -= rot(b, 14); \
	a ^= c; a -= rot(c, 11); \
	b ^= a; b -= rot(a, 25); \
	c ^= b; c -= rot(b, 16); \
	a ^= c; a -= rot(c,  4);\
	b ^= a; b -= rot(a, 14); \
	c ^= b; c -= rot(b, 24); \
}

#if (BYTE_ORDER == LITTLE_ENDIAN)
#define HASH_LITTLE_ENDIAN	1
#else
#define HASH_LITTLE_ENDIAN	0
#endif

/*
 *
 * hashlittle() -- hash a variable-length key into a 32-bit value
 *   k       : the key (the unaligned variable-length array of bytes)
 *   length  : the length of the key, counting by bytes
 *   initval : can be any 4-byte value
 * Returns a 32-bit value.  Every bit of the key affects every bit of
 * the return value.  Two keys differing by one or two bits will have
 * totally different hash values.
 * 
 * The best hash table sizes are powers of 2.  There is no need to do
 * mod a prime (mod is sooo slow!).  If you need less than 32 bits,
 * use a bitmask.  For example, if you need only 10 bits, do
 *   h = (h & hashmask(10));
 * In which case, the hash table should have hashsize(10) elements.
 * 
 * If you are hashing n strings (uint8_t **)k, do it like this:
 *   for (i = 0, h = 0; i < n; ++i) h = hashlittle(k[i], len[i], h);
 * 
 * By Bob Jenkins, 2006.  bob_jenkins@burtleburtle.net.  You may use this
 * code any way you wish, private, educational, or commercial.  It's free.
 * 
 * Use for hash table lookup, or anything where one collision in 2^^32 is
 * acceptable.  Do NOT use for cryptographic purposes.
 */
static
uint32_t hashlittle(const void *key, size_t length, uint32_t initval)
{
	uint32_t a, b, c;	/* internal state */
	union {
		const void *ptr;
		size_t i;
	} u;

	/* Set up the internal state */
	a = b = c = 0xdeadbeef + ((uint32_t)length) + initval;

	u.ptr = key;
	if (HASH_LITTLE_ENDIAN && ((u.i & 0x3) == 0)) {
		const uint32_t *k = (const uint32_t *) key;	/* read 32-bit chunks */

		/*------ all but last block: aligned reads and affect 32 bits of (a,b,c) */
		while (length > 12) {
			a += k[0];
			b += k[1];
			c += k[2];
			mix(a, b, c);
			length -= 12;
			k += 3;
		}

		/*----------------------------- handle the last (probably partial) block */
		/* 
		 * "k[2]&0xffffff" actually reads beyond the end of the string, but
		 * then masks off the part it's not allowed to read.	Because the
		 * string is aligned, the masked-off tail is in the same word as the
		 * rest of the string.	Every machine with memory protection I've seen
		 * does it on word boundaries, so is OK with this.	But VALGRIND will
		 * still catch it and complain.	The masking trick does make the hash
		 * noticably faster for short strings (like English words).
		 */
#ifndef VALGRIND

		switch (length) {
		case 12: c+=k[2]; b+=k[1]; a+=k[0]; break;
		case 11: c+=k[2]&0xffffff; b+=k[1]; a+=k[0]; break;
		case 10: c+=k[2]&0xffff; b+=k[1]; a+=k[0]; break;
		case 9 : c+=k[2]&0xff; b+=k[1]; a+=k[0]; break;
		case 8 : b+=k[1]; a+=k[0]; break;
		case 7 : b+=k[1]&0xffffff; a+=k[0]; break;
		case 6 : b+=k[1]&0xffff; a+=k[0]; break;
		case 5 : b+=k[1]&0xff; a+=k[0]; break;
		case 4 : a+=k[0]; break;
		case 3 : a+=k[0]&0xffffff; break;
		case 2 : a+=k[0]&0xffff; break;
		case 1 : a+=k[0]&0xff; break;
		case 0 : return c;		/* zero length strings require no mixing */
		}

#else /* make valgrind happy */
		{
			const uint8_t *k8;

			k8 = (const uint8_t *) k;
			switch (length) {
			case 12: c+=k[2]; b+=k[1]; a+=k[0]; break;
			case 11: c+=((uint32_t) k8[10])<<16;	/* fall through */
			case 10: c+=((uint32_t) k8[9])<<8;	/* fall through */
			case 9 : c+=k8[8];			/* fall through */
			case 8 : b+=k[1]; a+=k[0]; break;
			case 7 : b+=((uint32_t) k8[6])<<16;	/* fall through */
			case 6 : b+=((uint32_t) k8[5])<<8;	/* fall through */
			case 5 : b+=k8[4];			/* fall through */
			case 4 : a+=k[0]; break;
			case 3 : a+=((uint32_t) k8[2])<<16;	/* fall through */
			case 2 : a+=((uint32_t) k8[1])<<8;	/* fall through */
			case 1 : a+=k8[0]; break;
			case 0 : return c;
			}
		}
#endif /* !valgrind */

	} else if (HASH_LITTLE_ENDIAN && ((u.i & 0x1) == 0)) {
		const uint16_t *k = (const uint16_t *) key;	/* read 16-bit chunks */
		const uint8_t *k8;

		/*--------------- all but last block: aligned reads and different mixing */
		while (length > 12)
		{
			a += k[0] + (((uint32_t) k[1])<<16);
			b += k[2] + (((uint32_t) k[3])<<16);
			c += k[4] + (((uint32_t) k[5])<<16);
			mix(a, b, c);
			length -= 12;
			k += 6;
		}

		/*----------------------------- handle the last (probably partial) block */
		k8 = (const uint8_t *) k;
		switch(length)
		{
		case 12: c+=k[4]+(((uint32_t) k[5])<<16);
			 b+=k[2]+(((uint32_t) k[3])<<16);
			 a+=k[0]+(((uint32_t) k[1])<<16);
			 break;
		case 11: c+=((uint32_t) k8[10])<<16;	/* fall through */
		case 10: c+=k[4];
			 b+=k[2]+(((uint32_t) k[3])<<16);
			 a+=k[0]+(((uint32_t) k[1])<<16);
			 break;
		case 9 : c+=k8[8];			/* fall through */
		case 8 : b+=k[2]+(((uint32_t) k[3])<<16);
			 a+=k[0]+(((uint32_t) k[1])<<16);
			 break;
		case 7 : b+=((uint32_t) k8[6])<<16;	/* fall through */
		case 6 : b+=k[2];
			 a+=k[0]+(((uint32_t) k[1])<<16);
			 break;
		case 5 : b+=k8[4];			/* fall through */
		case 4 : a+=k[0]+(((uint32_t) k[1])<<16);
			 break;
		case 3 : a+=((uint32_t) k8[2])<<16;	/* fall through */
		case 2 : a+=k[0];
			 break;
		case 1 : a+=k8[0];
			 break;
		case 0 : return c;			/* zero length requires no mixing */
		}

	} else {					/* need to read the key one byte at a time */
		const uint8_t *k = (const uint8_t *)key;

		/*--------------- all but the last block: affect some 32 bits of (a, b, c) */
		while (length > 12) {
			a += k[0];
			a += ((uint32_t) k[1])<<8;
			a += ((uint32_t) k[2])<<16;
			a += ((uint32_t) k[3])<<24;
			b += k[4];
			b += ((uint32_t) k[5])<<8;
			b += ((uint32_t) k[6])<<16;
			b += ((uint32_t) k[7])<<24;
			c += k[8];
			c += ((uint32_t) k[9])<<8;
			c += ((uint32_t) k[10])<<16;
			c += ((uint32_t) k[11])<<24;
			mix(a,b,c);
			length -= 12;
			k += 12;
		}

		/*-------------------------------- last block: affect all 32 bits of (c) */
		switch (length) {		 /* all the case statements fall through */
		case 12: c+=((uint32_t) k[11])<<24;
		case 11: c+=((uint32_t) k[10])<<16;
		case 10: c+=((uint32_t) k[9])<<8;
		case 9 : c+=k[8];
		case 8 : b+=((uint32_t) k[7])<<24;
		case 7 : b+=((uint32_t) k[6])<<16;
		case 6 : b+=((uint32_t) k[5])<<8;
		case 5 : b+=k[4];
		case 4 : a+=((uint32_t) k[3])<<24;
		case 3 : a+=((uint32_t) k[2])<<16;
		case 2 : a+=((uint32_t) k[1])<<8;
		case 1 : a+=k[0];
			 break;
		case 0 : return c;
		}
	}

	final(a, b, c);
	return c;
}

static inline
uint32_t jhash(const void *key, size_t length, uint32_t seed)
{
	return hashlittle(key, length, seed);
}
