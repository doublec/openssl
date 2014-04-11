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

unsigned int get_record_length(SSL* s);
unsigned char* get_record_data(SSL* s);
unsigned short c_n2s (unsigned char* p);
void c_s2n (unsigned short s, unsigned char* p);
typedef void (*c_msg_callback)(int,int,int,const void*,size_t,SSL*,void*);
c_msg_callback get_msg_callback(SSL* s);
void* get_msg_callback_arg(SSL* s);
void call_msg_callback(c_msg_callback cb,
                       int write_p,
                       int version,
                       int content_type,
                       const void* buf,
                       size_t len,
                       SSL* ssl,
                       void* arg);
int get_version (SSL* s);
unsigned int get_tlsext_hb_seq (SSL* s);
void increment_tlsext_hb_seq (SSL* s);
void set_tlsext_hb_pending (SSL* s, unsigned int n);
void* null_ptr1 ();
%}
