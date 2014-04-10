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

void* c_s2n (unsigned short s, unsigned char* p) {
  s2n(s, p);
  return p;
}

void* ptr_add (void* p, int n) { return p + n; }

typedef void (*c_msg_callback)(int,int,int,const void*,size_t,SSL*,void*);
c_msg_callback get_msg_callback(SSL* s) { return s->msg_callback; }
void* get_msg_callback_arg(SSL* s) { return s->msg_callback_arg; }
void call_msg_callback(c_msg_callback cb, int write_p, int version, int content_type, const void* buf, size_t len, SSL* ssl, void* arg) {
  cb(write_p, version, content_type, buf, len, ssl, arg);
}

int get_version (SSL* s) { return s->version; }


unsigned int get_tlsext_hb_seq (SSL* s) { return s->tlsext_hb_seq; }
void increment_tlsext_hb_seq (SSL* s) { s->tlsext_hb_seq++; }
void set_tlsext_hb_pending (SSL* s, unsigned int n) { s->tlsext_hb_pending = n; }
%}

extern fun get_rrec (s: SSLptr): [l:addr] (SSL3_RECORD @ l | ptr l) = "mac#get_rrec"
extern fun c_n2s (c: ptr): usint = "mac#c_n2s"
extern fun ptr_add (p: ptr, n: int): ptr = "mac#ptr_add"

fun n2s (c: ptr): (ptr, int) = let
  val s = c_n2s(c)
in
  (ptr0_succ<usint> (c), $UN.cast2int(s))
end

typedef msg_callback = (int, int, int, ptr, size_t, SSLptr, ptr) -<fun> void
extern fun get_msg_callback (s: SSLptr): ptr = "mac#get_msg_callback"
extern fun get_msg_callback_arg (s: SSLptr): ptr = "mac#get_msg_callback_arg"
extern fun call_msg_callback (cb: ptr, write_p: int, version: int, content_type: int, buf: ptr, len: uint, ssl: SSLptr, arg: ptr): void = "mac#call_msg_callback"
extern fun get_version (s: SSLptr): int = "mac#get_version"

macdef TLS1_RT_HEARTBEAT = $extval(int, "TLS1_RT_HEARTBEAT")
macdef TLS1_HB_REQUEST = $extval(uchar, "TLS1_HB_REQUEST")
macdef TLS1_HB_RESPONSE = $extval(uchar, "TLS1_HB_RESPONSE")

extern fun OPENSSL_malloc {n:nat} (n: int n): [l:addr] (b0ytes(n) @ l | ptr l) = "mac#OPENSSL_malloc"
extern fun OPENSSL_free {l:addr} {n:nat} (pf: b0ytes(n) @ l | p: ptr l): void = "mac#OPENSSL_free"
extern fun unsafe_memcpy (d: ptr, s: ptr, n: int): void = "mac#memcpy"
extern fun safe_memcpy {l,l2:addr} {n1,n2:int} {n:int | n <= n1; n <= n2} 
            (pf_dst: !b0ytes(n1) @ l >> bytes(n1) @ l, pf_src: !bytes(n2) @ l2 |
             dst: ptr l, src: ptr l2, n: int n): void = "mac#memcpy"
extern fun RAND_pseudo_bytes (p: ptr, n: int): void = "mac#RAND_pseudo_bytes"
extern fun dtls1_write_bytes (s: SSLptr, type: int, buf: ptr, len: int): int = "mac#dtls1_write_bytes"
extern fun dtls1_stop_timer (s: SSLptr): void = "mac#dtls1_stop_timer"
extern fun get_tlsext_hb_seq (s: SSLptr): usint = "mac#get_tlsext_hb_seq"
extern fun increment_tlsext_hb_seq (s: SSLptr): void = "mac#increment_tlsext_hb_seq"
extern fun set_tlsext_hb_pending (s: SSLptr, n: uint): void = "mac#set_tlsext_hb_pending"

extern castfn to_int1 (n: int): [n:int] int n
extern castfn to_nat1 (n: uint): [n:nat] int n
extern castfn cast2byte {a:t0p} (x: INV(a)):<> byte

extern fun ptr_add_n {l:addr} {n:nat} {n2:nat | n2 >= n} (pf: !b0ytes(n2) @ l | p: ptr l, n: int n): 
              (b0ytes(n2 -n ) @ (l+n), (b0ytes(n2-n) @ (l+n)) -<lin,prf> void | ptr (l+n)) = "mac#ptr_add"

extern fun s2n {l:addr} {n:nat | n >= 2} (pf: !b0ytes(n) @ l | s: int, c: ptr l): 
              (b0ytes(n - 2) @ (l+2), (b0ytes(n - 2) @ (l+2)) -<lin,prf> void | ptr (l+2)) = "mac#c_s2n"

fun ats_dtls1_process_heartbeat(s: SSLptr): int = let
  val padding = 16
  val (pf_rrec | p_rrec) = get_rrec (s) 
  val p = p_rrec->data
  val hbtype = $UN.ptr0_get<uchar> (p)
  val p = ptr0_succ<uchar> (p)
  val (p, payload) = n2s (p)
  val payload = to_int1 (payload)
  val [rn:int] rrec_length = to_nat1(p_rrec->length)

  val (pf_pl, pff_pl | pl)  = __hack(p) where { extern castfn __hack (p: ptr): [l:addr] [n:nat | n == rn - 1 - 2 - 16 ] (bytes(n) @ l, bytes(n) @ l -<lin,prf> void | ptr l) }

  val () = if (ptr_isnot_null (get_msg_callback (s))) then 
             call_msg_callback (get_msg_callback (s),
                                0, get_version (s), TLS1_RT_HEARTBEAT,
                                p_rrec->data, p_rrec->length, s,
                                get_msg_callback_arg (s))
  prval () = _consume (pf_rrec) where { extern prfun _consume {l:addr} (s: SSL3_RECORD @ l): void }


in
  if hbtype = TLS1_HB_REQUEST then  let
    val n = to_int1 (1 + 2 + payload + padding)
    val () = assertloc (n > 1 + 2 + padding)
    val (pf_buffer | buffer) = OPENSSL_malloc(n)

    val () = !buffer.[0] := cast2byte(TLS1_HB_RESPONSE)
    val (pf_bp, pff_bp | bp) = ptr_add_n (pf_buffer | buffer, 1)
    val (pf_bp2, pff_bp2 | bp2) = s2n (pf_bp | payload, bp)

    (* Won't compile without these assertions *)
    val () = assertloc (rrec_length >= 1 + 2 + payload + 16)
    val () = assertloc (payload <= n - 3)

    val () = safe_memcpy (pf_bp2, pf_pl | bp2, pl, payload)
    prval () = pff_pl (pf_pl)
    prval () = pff_bp2(pf_bp2)
    prval () = pff_bp(pf_bp);

    val bp = ptr_add (bp2, payload)
    val () = RAND_pseudo_bytes (bp, padding)
    val r = dtls1_write_bytes (s, TLS1_RT_HEARTBEAT, buffer, 3 + $UN.cast2int(payload) + padding)
    val () = if r >=0 && ptr_isnot_null (get_msg_callback (s)) then 
               call_msg_callback (get_msg_callback (s),
                                  1, get_version (s), TLS1_RT_HEARTBEAT,
                                  buffer, $UN.cast2uint (3 + $UN.cast2int(payload) + padding), s,
                                  get_msg_callback_arg (s))
    val () = OPENSSL_free (pf_buffer | buffer)
  in
    if r < 0 then r else 0    
  end else if hbtype = TLS1_HB_RESPONSE then let
    val (pl, seq) = n2s (pl)
    prval () = pff_pl(pf_pl)
  in
    if $UN.cast2int(payload) = 18  && $UN.cast2int(seq) = $UN.cast2int(get_tlsext_hb_seq (s)) then let
      val () = dtls1_stop_timer (s)
      val () = increment_tlsext_hb_seq (s)
      val () = set_tlsext_hb_pending (s, $UN.cast2uint(0))  
    in 0
    end else 0
  end else let
    prval () = pff_pl(pf_pl)
  in 0 end
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

implement dtls1_process_heartbeat (s) = ats_dtls1_process_heartbeat (s)
