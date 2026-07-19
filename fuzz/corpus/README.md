# Seed Corpus

Corpus entries prefixed with `hex:` are decoded by the corresponding fuzz
target before parsing. This keeps packet bytes reviewable in Git. The initial
seeds cover valid protocol examples and length/option boundaries derived from
the regression suite. Sanitized packets from manually captured test traffic
can be added in the same form; remove payloads and addresses that identify a
real network before committing them.

`dhcp_options/wireshark_dhcp_discover.hex` is the BOOTP payload from the first
packet in Wireshark's `test/captures/dhcp.pcap`. The transaction ID and client
MAC address were replaced before inclusion. Source:
<https://gitlab.com/wireshark/wireshark/-/blob/master/test/captures/dhcp.pcap>.
