# How to read metamako timestamps in Rust

This is mainly an educational exercise for me to understand how network captures (legacy pcaps) work.

## Sources
* The metamako capture is sourced from [Wireshark's wiki](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/metamako_trailer.pcap).
* The following libraries are used:
    * [Pcap Parser](https://docs.rs/pcap-parser/latest/pcap_parser): This reads pcap files from captures
    * [Byteorder](https://docs.rs/byteorder/latest/byteorder/): This does the classic `ntohs` conversions.
    * [Etherparse](https://docs.rs/etherparse/latest/etherparse/): Although ultimately unused, you may find this library useful to do any actual work on pcaps. This is not necessary to decode the metamako data, as it is all in the trailer.
