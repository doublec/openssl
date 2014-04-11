(* ATS wrappers for C functions and various OpenSSL/C routines *)
abst@ype SSLptr = $extype "SSL*"

fun get_record_length (s: SSLptr): [n:nat] size_t n = "mac#get_record_length"
fun get_record_data (s: SSLptr): [l:agz] ptr l = "mac#get_record_data"
fun c_n2s (c: ptr): usint = "mac#c_n2s"
fun s2n {l:addr} {n:nat | n >= 2} (pf: !array_v (byte, l, n) | s: size_t, c: ptr l):  void = "mac#c_s2n"

fun get_msg_callback (s: SSLptr): ptr = "mac#get_msg_callback"
fun get_msg_callback_arg (s: SSLptr): ptr = "mac#get_msg_callback_arg"
fun call_msg_callback (cb: ptr, write_p: int, version: int,
                              content_type: int, buf: ptr, len: size_t,
                              ssl: SSLptr, arg: ptr): void = "mac#call_msg_callback"
fun get_version (s: SSLptr): int = "mac#get_version"
fun null_ptr1 (): ptr null = "mac#null_ptr1"

macdef TLS1_RT_HEARTBEAT = $extval(int, "TLS1_RT_HEARTBEAT")
macdef TLS1_HB_REQUEST   = $extval(int, "TLS1_HB_REQUEST")
macdef TLS1_HB_RESPONSE  = $extval(int, "TLS1_HB_RESPONSE")

fun OPENSSL_malloc {n:nat} (n: size_t n):
             [l:agz] (array_v (byte?, l, n) | ptr l) = "mac#OPENSSL_malloc"
fun OPENSSL_free {l:addr} {n:nat} (pf: array_v (byte?, l, n) |
                        p: ptr l):
                        void = "mac#OPENSSL_free"
fun safe_memcpy {l,l2:addr} {n1,n2:int} {n:int | n <= n1; n <= n2} 
            (pf_dst: !array_v (byte?, l, n1) >> array_v (byte, l, n1), pf_src: !array_v(byte, l2, n2) |
             dst: ptr l, src: ptr l2, n: size_t n):
             void = "mac#memcpy"
fun RAND_pseudo_bytes {l:addr} {n:nat}
                             (pf: !array_v (byte, l, n) | p: ptr l, n: size_t n):
                              void = "mac#RAND_pseudo_bytes"
fun dtls1_write_bytes {l:addr} {n:nat}
                             (pf: !array_v (byte, l, n) |
                              s: SSLptr, type: int, buf: ptr l, len: size_t n):
                             int = "mac#dtls1_write_bytes"
fun ssl3_write_bytes {l:addr} {n:nat}
                             (pf: !array_v (byte, l, n) |
                              s: SSLptr, type: int, buf: ptr l, len: size_t n):
                             int = "mac#ssl3_write_bytes"
fun dtls1_stop_timer (s: SSLptr): void = "mac#dtls1_stop_timer"
fun get_tlsext_hb_seq (s: SSLptr): usint = "mac#get_tlsext_hb_seq"
fun increment_tlsext_hb_seq (s: SSLptr): void = "mac#increment_tlsext_hb_seq"
fun set_tlsext_hb_pending (s: SSLptr, n: uint): void = "mac#set_tlsext_hb_pending"

castfn cast2byte {a:t0p} (x: INV(a)):<> byte
castfn usint_to_size1 (n: usint): [n:nat] size_t n

fun n2s {l:addr} (c: ptr l): [n:nat] size_t n

(* A view for an array  that contains:
     byte    = hbtype
     ushort  = payload length
     byte[n] = bytes of length 'payload length'
     byte[16]= padding
*)
dataview record_data_v (addr, int) =
  | {l:agz} {n:nat | n > 16 + 2 + 1} make_record_data_v (l, n) of (ptr l, size_t n)
  | record_data_v_fail (null, 0) of ()

prfun free_record_data_v {l:addr} {n:nat} (pf: record_data_v (l, n)): void

fun get_record (s: SSLptr): [l:addr] [n:nat] (record_data_v (l, n) | ptr l, size_t n)

(* These proof functions extract proofs out of the record_data_v
   to allow access to the data stored in the record. The constants
   for the size of the padding, payload buffer, etc are checked
   within the proofs so that functions that manipulate memory
   are checked that they remain within the correct bounds and
   use the appropriate pointer values
*)
prfun extract_data_proof {l:agz} {n:nat}
               (pf: record_data_v (l, n)):
               (array_v (byte, l, n),
                array_v (byte, l, n) -<lin,prf> record_data_v (l,n))
prfun extract_hbtype_proof {l:agz} {n:nat}
               (pf: record_data_v (l, n)):
               (byte @ l, byte @ l -<lin,prf> record_data_v (l,n))
prfun extract_payload_length_proof {l:agz} {n:nat}
               (pf: record_data_v (l, n)):
               (array_v (byte, l+1, 2),
                array_v (byte, l+1, 2) -<lin,prf> record_data_v (l,n))
prfun extract_payload_data_proof {l:agz} {n:nat}
               (pf: record_data_v (l, n)):
               (array_v (byte, l+1+2, n-16-2-1),
                array_v (byte, l+1+2, n-16-2-1) -<lin,prf> record_data_v (l,n))
prfun extract_padding_proof {l:agz} {n:nat} {n2:nat | n2 <= n - 16 - 2 - 1}
               (pf: record_data_v (l, n), payload_length: size_t n2):
               (array_v (byte, l + n2 + 1 + 2, 16),
                array_v (byte, l + n2 + 1 + 2, 16) -<lin, prf> record_data_v (l, n))


