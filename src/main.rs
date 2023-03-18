use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use std::fs::File;
// use etherparse::SlicedPacket;
use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt};
use chrono::NaiveDateTime;

fn main() {
    let path = "./metamako_trailer.pcap";
    let file = File::open(path).unwrap();
    let mut num_blocks = 0;
    let mut reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");
    let mut count = 0;
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                num_blocks += 1;
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        println!("HEADER {:?}", hdr);
                        // save hdr.network (linktype)
                    }
                    PcapBlockOwned::Legacy(b) => {
                        println!("{:02X?}", b.data);
                        let time = NaiveDateTime::from_timestamp_opt(b.ts_sec.into(), b.ts_usec).unwrap();
                        println!("{:?}", time);
                        let mut it = b.data.rchunks(4);
                        it.next();
                        it.next();
                        let nanosecond_chunk = Cursor::new(it.next().unwrap()).read_u32::<BigEndian>().unwrap();
                        let second_chunk = Cursor::new(it.next().unwrap()).read_u32::<BigEndian>().unwrap();
                        let time = NaiveDateTime::from_timestamp_opt(second_chunk.into(), nanosecond_chunk).unwrap();
                        println!("{:?}", time);
                        // match SlicedPacket::from_ethernet(&b.data) {
                        //     Err(value) => println!("Err {:?}", value),
                        //     Ok(value) => {
                        //         println!("{:02X?}", value);
                        //         let mut it = value.payload.rchunks(4);
                        //         it.next();
                        //         it.next();
                        //         let nanosecond_chunk = Cursor::new(it.next().unwrap()).read_u32::<BigEndian>().unwrap();
                        //         let second_chunk = Cursor::new(it.next().unwrap()).read_u32::<BigEndian>().unwrap();
                        //         let time = NaiveDateTime::from_timestamp_opt(second_chunk.into(), nanosecond_chunk).unwrap();
                        //         println!("{:?}", time);
                        //     }
                        // }
                        // use linktype to parse b.data()
                    }
                    PcapBlockOwned::NG(_) => unreachable!(),
                }
                reader.consume(offset);
                count += 1;
                println!("");
                if count > 10 {
                    break;
                }
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    println!("num_blocks: {}", num_blocks);
}
