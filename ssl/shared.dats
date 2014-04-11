staload UN = "prelude/SATS/unsafe.sats"
staload "shared.sats"

#include "share/atspre_staload.hats"

#define ATS_DYNLOADFLAG 0

#include "shared.cats"

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

implement n2s (c) = let
  val s = c_n2s(c)
in
  usint_to_size1 (s)
end

implement get_record (s) = let
  val len = get_record_length (s)
  val data = get_record_data (s)
in
  if len > 16 + 2 + 1 then
    (make_record_data_v (data, len) | data, len)
  else
    (record_data_v_fail () | null_ptr1 (), i2sz 0)
end


