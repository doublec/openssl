staload UN = "prelude/SATS/unsafe.sats"
staload "shared.sats"
#include "share/atspre_staload.hats"

#define ATS_DYNLOADFLAG 0

(* The size in bytes of the padding buffer in the request/response *)
#define PADDING 16

#include "shared.cats"

extern fun tls1_process_heartbeat (s: SSLptr): int = "ext#tls1_process_heartbeat"

implement tls1_process_heartbeat(s) =
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
              val r = ssl3_write_bytes (pf | s, TLS1_RT_HEARTBEAT, p_buffer, n)
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
