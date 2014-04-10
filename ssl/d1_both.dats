staload UN = "prelude/SATS/unsafe.sats"
#include "share/atspre_staload.hats"

#define ATS_DYNLOADFLAG 0

%{^
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
%}

typedef SSL3_RECORD = $extype_struct "SSL3_RECORD" of {
  type = int,          (* type of record *)
  length = uint,       (* How many bytes available *)
  orig_len = uint,     (* How many bytes were available before padding
                          was removed? This is used to implement the
                          MAC check in constant time for CBC records.
                       *)
  off = uint,          (* read/write offset into 'buf' *)
  data = ptr,          (* pointer to the record data - uchar* *)
  input = ptr,         (* where the decode bytes are - uchar* *)
  comp = ptr,          (* only used with decompression - malloc()edi - uchar* *)
  epoch = lint,        (* epoch number, needed by DTLS1 *)
  seq_num = @[char][8] (* sequence number, needed by DTLS1 *)
}
typedef SSL3_RECORDptr = $extype "SSL3_RECORD*"
abst@ype SSLptr = $extype "SSL*"

%{
/* Helper routines to access fields of C structures */
SSL3_RECORD* get_rrec(SSL* s) { return &s->s3->rrec; }

unsigned short c_n2s (unsigned char* p) {
  unsigned short s;
  n2s(p, s);
  return s;
}

typedef void (*c_msg_callback)(int,int,int,const void*,size_t,SSL*,void*);
c_msg_callback get_msg_callback(SSL* s) { return s->msg_callback; }
void* get_msg_callback_arg(SSL* s) { return s->msg_callback_arg; }
void call_msg_callback(c_msg_callback cb, int write_p, int version, int content_type, const void* buf, size_t len, SSL* ssl, void* arg) {
  cb(write_p, version, content_type, buf, len, ssl, arg);
}

int get_version (SSL* s) { return s->version; }
%}

extern fun get_rrec (s: SSLptr): [l:addr] (SSL3_RECORD @ l | ptr l) = "mac#get_rrec"
extern fun c_n2s (c: ptr): usint = "mac#c_n2s"
fun n2s (c: ptr): (ptr, usint) = let
  val s = c_n2s(c)
in
  (ptr0_succ<usint> (c), s)
end

typedef msg_callback = (int, int, int, ptr, size_t, SSLptr, ptr) -<fun> void
extern fun get_msg_callback (s: SSLptr): ptr = "mac#get_msg_callback"
extern fun get_msg_callback_arg (s: SSLptr): ptr = "mac#get_msg_callback_arg"
extern fun call_msg_callback (cb: ptr, write_p: int, version: int, content_type: int, buf: ptr, len: uint, ssl: SSLptr, arg: ptr): void = "mac#call_msg_callback"
extern fun get_version (s: SSLptr): int = "mac#get_version"

macdef TLS_RT_HEARTBEAT = $extval(int, "TLS_RT_HEARTBEAT")

fun ats_dtls1_process_heartbeat(s: SSLptr): int = let
  val (pf_rrec | p_rrec) = get_rrec (s) 
  val p = p_rrec->data
  val hbtype = $UN.ptr0_get<uchar> (p)
  val p = ptr0_succ<uchar> (p)
  val (p, payload) = n2s (p)
  val pl = p

  val () = if (ptr_isnot_null (get_msg_callback (s))) then 
             call_msg_callback (get_msg_callback (s),
                                0, get_version (s), TLS_RT_HEARTBEAT,
                                p_rrec->data, p_rrec->length, s,
                                get_msg_callback_arg (s))

  prval () = _consume (pf_rrec) where { extern prfun _consume {l:addr} (s: SSL3_RECORD @ l): void }
in
  0
end

%{
int
c_dtls1_process_heartbeat(SSL *s)
	{
	unsigned char *p = &s->s3->rrec.data[0], *pl;
	unsigned short hbtype;
	unsigned int payload;
	unsigned int padding = 16; /* Use minimum padding */

	/* Read type and payload length first */
	hbtype = *p++;
	n2s(p, payload);
	pl = p;

	if (s->msg_callback)
		s->msg_callback(0, s->version, TLS1_RT_HEARTBEAT,
			&s->s3->rrec.data[0], s->s3->rrec.length,
			s, s->msg_callback_arg);

	if (hbtype == TLS1_HB_REQUEST)
		{
		unsigned char *buffer, *bp;
		int r;

		/* Allocate memory for the response, size is 1 byte
		 * message type, plus 2 bytes payload length, plus
		 * payload, plus padding
		 */
		buffer = OPENSSL_malloc(1 + 2 + payload + padding);
		bp = buffer;

		/* Enter response type, length and copy payload */
		*bp++ = TLS1_HB_RESPONSE;
		s2n(payload, bp);
		memcpy(bp, pl, payload);
		bp += payload;
		/* Random padding */
		RAND_pseudo_bytes(bp, padding);

		r = dtls1_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);

		if (r >= 0 && s->msg_callback)
			s->msg_callback(1, s->version, TLS1_RT_HEARTBEAT,
				buffer, 3 + payload + padding,
				s, s->msg_callback_arg);

		OPENSSL_free(buffer);

		if (r < 0)
			return r;
		}
	else if (hbtype == TLS1_HB_RESPONSE)
		{
		unsigned int seq;

		/* We only send sequence numbers (2 bytes unsigned int),
		 * and 16 random bytes, so we just try to read the
		 * sequence number */
		n2s(pl, seq);

		if (payload == 18 && seq == s->tlsext_hb_seq)
			{
			dtls1_stop_timer(s);
			s->tlsext_hb_seq++;
			s->tlsext_hb_pending = 0;
			}
		}

	return 0;
	}
%}

extern fun c_dtls1_process_heartbeat (s: SSLptr): int = "mac#c_dtls1_process_heartbeat"
extern fun dtls1_process_heartbeat (s: SSLptr): int = "ext#dtls1_process_heartbeat"

implement dtls1_process_heartbeat (s) = c_dtls1_process_heartbeat (s)
