staload UN = "prelude/SATS/unsafe.sats"
#include "share/atspre_staload.hats"

#define ATS_DYNLOADFLAG 0

(* The size in bytes of the padding buffer in the request/response *)
#define PADDING 16

%{^
/* C header files needed to use OpenSSL functions */
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

abst@ype SSLptr = $extype "SSL*"

%{
/* Some wrapper code written in C to make it easier to access
   fields in OpenSSL structures. This could be done in ATS
   but quicker to prototype in C.
*/
unsigned int get_record_length(SSL* s) { return s->s3->rrec.length; } 
unsigned char* get_record_data(SSL* s) { return &s->s3->rrec.data[0]; }

unsigned short c_n2s (unsigned char* p) {
  unsigned short s;
  n2s(p, s);
  return s;
}

void c_s2n (unsigned short s, unsigned char* p) {
  s2n(s, p);
}

typedef void (*c_msg_callback)(int,int,int,const void*,size_t,SSL*,void*);
c_msg_callback get_msg_callback(SSL* s) { return s->msg_callback; }
void* get_msg_callback_arg(SSL* s) { return s->msg_callback_arg; }
void call_msg_callback(c_msg_callback cb,
                       int write_p,
                       int version,
                       int content_type,
                       const void* buf,
                       size_t len,
                       SSL* ssl,
                       void* arg) {
  cb(write_p, version, content_type, buf, len, ssl, arg);
}

int get_version (SSL* s) { return s->version; }
unsigned int get_tlsext_hb_seq (SSL* s) { return s->tlsext_hb_seq; }
void increment_tlsext_hb_seq (SSL* s) { s->tlsext_hb_seq++; }
void set_tlsext_hb_pending (SSL* s, unsigned int n) { s->tlsext_hb_pending = n; }
void* null_ptr1 () { return 0; }
%}

(* ATS wrappers for the above C functions and various OpenSSL/C routines *)
extern fun get_record_length (s: SSLptr): [n:nat] size_t n = "mac#get_record_length"
extern fun get_record_data (s: SSLptr): [l:agz] ptr l = "mac#get_record_data"
extern fun c_n2s (c: ptr): usint = "mac#c_n2s"
extern fun s2n {l:addr} {n:nat | n >= 2} (pf: !array_v (byte, l, n) | s: size_t, c: ptr l):  void = "mac#c_s2n"

extern fun get_msg_callback (s: SSLptr): ptr = "mac#get_msg_callback"
extern fun get_msg_callback_arg (s: SSLptr): ptr = "mac#get_msg_callback_arg"
extern fun call_msg_callback (cb: ptr, write_p: int, version: int,
                              content_type: int, buf: ptr, len: size_t,
                              ssl: SSLptr, arg: ptr): void = "mac#call_msg_callback"
extern fun get_version (s: SSLptr): int = "mac#get_version"
extern fun null_ptr1 (): ptr null = "mac#null_ptr1"

macdef TLS1_RT_HEARTBEAT = $extval(int, "TLS1_RT_HEARTBEAT")
macdef TLS1_HB_REQUEST   = $extval(int, "TLS1_HB_REQUEST")
macdef TLS1_HB_RESPONSE  = $extval(int, "TLS1_HB_RESPONSE")

extern fun OPENSSL_malloc {n:nat} (n: size_t n):
             [l:agz] (array_v (byte?, l, n) | ptr l) = "mac#OPENSSL_malloc"
extern fun OPENSSL_free {l:addr} {n:nat} (pf: array_v (byte?, l, n) |
                        p: ptr l):
                        void = "mac#OPENSSL_free"
extern fun safe_memcpy {l,l2:addr} {n1,n2:int} {n:int | n <= n1; n <= n2} 
            (pf_dst: !array_v (byte?, l, n1) >> array_v (byte, l, n1), pf_src: !array_v(byte, l2, n2) |
             dst: ptr l, src: ptr l2, n: size_t n):
             void = "mac#memcpy"
extern fun RAND_pseudo_bytes {l:addr} {n:nat}
                             (pf: !array_v (byte, l, n) | p: ptr l, n: size_t n):
                              void = "mac#RAND_pseudo_bytes"
extern fun dtls1_write_bytes {l:addr} {n:nat}
                             (pf: !array_v (byte, l, n) |
                              s: SSLptr, type: int, buf: ptr l, len: size_t n):
                             int = "mac#dtls1_write_bytes"
extern fun dtls1_stop_timer (s: SSLptr): void = "mac#dtls1_stop_timer"
extern fun get_tlsext_hb_seq (s: SSLptr): usint = "mac#get_tlsext_hb_seq"
extern fun increment_tlsext_hb_seq (s: SSLptr): void = "mac#increment_tlsext_hb_seq"
extern fun set_tlsext_hb_pending (s: SSLptr, n: uint): void = "mac#set_tlsext_hb_pending"

extern castfn cast2byte {a:t0p} (x: INV(a)):<> byte
extern castfn usint_to_size1 (n: usint): [n:nat] size_t n

fun n2s {l:addr} (c: ptr l): [n:nat] size_t n = let
  val s = c_n2s(c)
in
  usint_to_size1 (s)
end

(* A view for an array  that contains:
     byte    = hbtype
     ushort  = payload length
     byte[n] = bytes of length 'payload length'
     byte[16]= padding
*)
dataview record_data_v (addr, int) =
  | {l:agz} {n:nat | n > 16 + 2 + 1} make_record_data_v (l, n) of (ptr l, size_t n)
  | record_data_v_fail (null, 0) of ()

extern prfun free_record_data_v {l:addr} {n:nat} (pf: record_data_v (l, n)): void

fun get_record (s: SSLptr): [l:addr] [n:nat] (record_data_v (l, n) | ptr l, size_t n) = let
  val len = get_record_length (s)
  val data = get_record_data (s)
in
  if len > 16 + 2 + 1 then
    (make_record_data_v (data, len) | data, len)
  else
    (record_data_v_fail () | null_ptr1 (), i2sz 0)
end

(* These proof functions extract proofs out of the record_data_v
   to allow access to the data stored in the record. The constants
   for the size of the padding, payload buffer, etc are checked
   within the proofs so that functions that manipulate memory
   are checked that they remain within the correct bounds and
   use the appropriate pointer values
*)
extern prfun extract_data_proof {l:agz} {n:nat}
               (pf: record_data_v (l, n)):
               (array_v (byte, l, n),
                array_v (byte, l, n) -<lin,prf> record_data_v (l,n))
extern prfun extract_hbtype_proof {l:agz} {n:nat}
               (pf: record_data_v (l, n)):
               (byte @ l, byte @ l -<lin,prf> record_data_v (l,n))
extern prfun extract_payload_length_proof {l:agz} {n:nat}
               (pf: record_data_v (l, n)):
               (array_v (byte, l+1, 2),
                array_v (byte, l+1, 2) -<lin,prf> record_data_v (l,n))
extern prfun extract_payload_data_proof {l:agz} {n:nat}
               (pf: record_data_v (l, n)):
               (array_v (byte, l+1+2, n-16-2-1),
                array_v (byte, l+1+2, n-16-2-1) -<lin,prf> record_data_v (l,n))
extern prfun extract_padding_proof {l:agz} {n:nat} {n2:nat | n2 <= n - 16 - 2 - 1}
               (pf: record_data_v (l, n), payload_length: size_t n2):
               (array_v (byte, l + n2 + 1 + 2, 16),
                array_v (byte, l + n2 + 1 + 2, 16) -<lin, prf> record_data_v (l, n))


fun ats_dtls1_process_heartbeat(s: SSLptr): int =
let
  fun fail {l:addr} {n:nat} (pf: record_data_v (l, n)): int =
    let
      prval () = free_record_data_v (pf)
    in
      0
    end

  val padding = i2sz(PADDING)
  val (pf_data | p_data, data_len) = get_record (s)
in
  if ptr1_isnot_null (p_data) then
    let
      prval (pf, pff) = extract_hbtype_proof (pf_data)
      val hbtype = $UN.cast2int (!p_data)
      prval pf_data = pff (pf)

      prval (pf, pff) = extract_payload_length_proof (pf_data)
      val p = ptr_succ<byte> (p_data)
      val payload_length = n2s (p)
      prval pf_data = pff (pf)

      val () = if (ptr_isnot_null (get_msg_callback (s))) then 
                 call_msg_callback (get_msg_callback (s),
                                    0, get_version (s), TLS1_RT_HEARTBEAT,
                                    p_data, data_len, s,
                                    get_msg_callback_arg (s))

    in
      if hbtype = TLS1_HB_REQUEST then
        if payload_length > 0 then
          if data_len >= payload_length + padding + 1 + 2 then
            let
              val n = payload_length + padding + 1 + 2

              val (pf_buffer | p_buffer) = OPENSSL_malloc(n)
              prval pf_response = make_record_data_v (p_buffer, n)

              prval (pf, pff) = extract_hbtype_proof (pf_response)
              val () = !p_buffer := cast2byte(TLS1_HB_RESPONSE)
              prval pf_response = pff(pf)
 
              prval (pf, pff) = extract_payload_length_proof (pf_response)
              val p = add_ptr1_bsz (p_buffer, i2sz 1)
              val () = s2n (pf | payload_length, p)
              prval pf_response = pff(pf)

              prval (pf_dst, pff_dst) = extract_payload_data_proof (pf_response)
              prval (pf_src, pff_src) = extract_payload_data_proof (pf_data)
              val () = safe_memcpy (pf_dst, pf_src | add_ptr1_bsz (p_buffer, i2sz 3), add_ptr1_bsz (p_data, i2sz 3), payload_length)
              prval pf_response = pff_dst(pf_dst)
              prval pf_data = pff_src(pf_src)

              prval (pf, pff) = extract_padding_proof (pf_response, payload_length)
              val () = RAND_pseudo_bytes (pf | add_ptr_bsz (p_buffer, payload_length + 1 + 2), padding)
              prval pf_response = pff(pf)

              prval (pf, pff) = extract_data_proof (pf_response)
              val r = dtls1_write_bytes (pf | s, TLS1_RT_HEARTBEAT, p_buffer, n)
              prval pf_response = pff(pf)
  
              val () = if r >=0 && ptr_isnot_null (get_msg_callback (s)) then 
                         call_msg_callback (get_msg_callback (s),
                                            1, get_version (s), TLS1_RT_HEARTBEAT,
                                            p_buffer, n, s,
                                            get_msg_callback_arg (s))
              prval () = free_record_data_v (pf_data)
              prval () = free_record_data_v (pf_response)
              val () = OPENSSL_free (pf_buffer | p_buffer)
            in
              if r < 0 then r else 0    
            end
          else
            fail (pf_data)
        else
          fail (pf_data)
      else if hbtype = TLS1_HB_RESPONSE then
        let
          prval (pf, pff) = extract_payload_data_proof (pf_data)
          val seq = n2s (add_ptr1_bsz (p_data,  i2sz 3))
          prval pf_data = pff (pf)
          prval () = free_record_data_v (pf_data)
        in
          if $UN.cast2int(payload_length) = 18 &&
             $UN.cast2int(seq) = $UN.cast2int(get_tlsext_hb_seq (s)) then
            let
              val () = dtls1_stop_timer (s)
              val () = increment_tlsext_hb_seq (s)
              val () = set_tlsext_hb_pending (s, $UN.cast2uint(0))  
            in
              0
            end
          else
            0
        end
      else
        fail (pf_data)
    end
  else
    fail (pf_data)
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
