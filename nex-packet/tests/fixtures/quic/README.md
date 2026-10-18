# QUIC test vectors

The hexadecimal packet fixtures are the published protected wire packets from
Appendices A.2 (client Initial), A.3 (server Initial), and A.4 (Retry) of:

- RFC 9001: https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A
- RFC 9369: https://www.rfc-editor.org/rfc/rfc9369.html#appendix-A

Whitespace is insignificant. These fixtures validate public-header parsing and
lossless serialization; tests do not claim to authenticate or decrypt them.
