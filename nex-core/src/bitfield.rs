//! Provides type aliases for various primitive integer types
//!
//! These types are aliased to the next largest of \[`u8`, `u16`, `u32`, `u64`\]
//!
//! All aliases for types larger than `u8` contain a `be` or `le` suffix. These specify whether the
//! value is big or little endian, respectively. 

#![allow(non_camel_case_types)]
/// Represents an unsigned, 1-bit integer.
pub type u1 = u8;
/// Represents an unsigned, 2-bit integer.
pub type u2 = u8;
/// Represents an unsigned, 3-bit integer.
pub type u3 = u8;
/// Represents an unsigned, 4-bit integer.
pub type u4 = u8;
/// Represents an unsigned, 5-bit integer.
pub type u5 = u8;
/// Represents an unsigned, 6-bit integer.
pub type u6 = u8;
/// Represents an unsigned, 7-bit integer.
pub type u7 = u8;
/// Represents an unsigned 9-bit integer. 
pub type u9be = u16;
/// Represents an unsigned 10-bit integer. 
pub type u10be = u16;
/// Represents an unsigned 11-bit integer. 
pub type u11be = u16;
/// Represents an unsigned 12-bit integer. 
pub type u12be = u16;
/// Represents an unsigned 13-bit integer. 
pub type u13be = u16;
/// Represents an unsigned 14-bit integer. 
pub type u14be = u16;
/// Represents an unsigned 15-bit integer. 
pub type u15be = u16;
/// Represents an unsigned 16-bit integer. 
pub type u16be = u16;
/// Represents an unsigned 17-bit integer. 
pub type u17be = u32;
/// Represents an unsigned 18-bit integer. 
pub type u18be = u32;
/// Represents an unsigned 19-bit integer. 
pub type u19be = u32;
/// Represents an unsigned 20-bit integer. 
pub type u20be = u32;
/// Represents an unsigned 21-bit integer. 
pub type u21be = u32;
/// Represents an unsigned 22-bit integer. 
pub type u22be = u32;
/// Represents an unsigned 23-bit integer. 
pub type u23be = u32;
/// Represents an unsigned 24-bit integer. 
pub type u24be = u32;
/// Represents an unsigned 25-bit integer. 
pub type u25be = u32;
/// Represents an unsigned 26-bit integer. 
pub type u26be = u32;
/// Represents an unsigned 27-bit integer. 
pub type u27be = u32;
/// Represents an unsigned 28-bit integer. 
pub type u28be = u32;
/// Represents an unsigned 29-bit integer. 
pub type u29be = u32;
/// Represents an unsigned 30-bit integer. 
pub type u30be = u32;
/// Represents an unsigned 31-bit integer. 
pub type u31be = u32;
/// Represents an unsigned 32-bit integer. 
pub type u32be = u32;
/// Represents an unsigned 33-bit integer. 
pub type u33be = u64;
/// Represents an unsigned 34-bit integer. 
pub type u34be = u64;
/// Represents an unsigned 35-bit integer. 
pub type u35be = u64;
/// Represents an unsigned 36-bit integer. 
pub type u36be = u64;
/// Represents an unsigned 37-bit integer. 
pub type u37be = u64;
/// Represents an unsigned 38-bit integer. 
pub type u38be = u64;
/// Represents an unsigned 39-bit integer. 
pub type u39be = u64;
/// Represents an unsigned 40-bit integer. 
pub type u40be = u64;
/// Represents an unsigned 41-bit integer. 
pub type u41be = u64;
/// Represents an unsigned 42-bit integer. 
pub type u42be = u64;
/// Represents an unsigned 43-bit integer. 
pub type u43be = u64;
/// Represents an unsigned 44-bit integer. 
pub type u44be = u64;
/// Represents an unsigned 45-bit integer. 
pub type u45be = u64;
/// Represents an unsigned 46-bit integer. 
pub type u46be = u64;
/// Represents an unsigned 47-bit integer. 
pub type u47be = u64;
/// Represents an unsigned 48-bit integer. 
pub type u48be = u64;
/// Represents an unsigned 49-bit integer. 
pub type u49be = u64;
/// Represents an unsigned 50-bit integer. 
pub type u50be = u64;
/// Represents an unsigned 51-bit integer. 
pub type u51be = u64;
/// Represents an unsigned 52-bit integer. 
pub type u52be = u64;
/// Represents an unsigned 53-bit integer. 
pub type u53be = u64;
/// Represents an unsigned 54-bit integer. 
pub type u54be = u64;
/// Represents an unsigned 55-bit integer. 
pub type u55be = u64;
/// Represents an unsigned 56-bit integer. 
pub type u56be = u64;
/// Represents an unsigned 57-bit integer. 
pub type u57be = u64;
/// Represents an unsigned 58-bit integer. 
pub type u58be = u64;
/// Represents an unsigned 59-bit integer. 
pub type u59be = u64;
/// Represents an unsigned 60-bit integer. 
pub type u60be = u64;
/// Represents an unsigned 61-bit integer. 
pub type u61be = u64;
/// Represents an unsigned 62-bit integer. 
pub type u62be = u64;
/// Represents an unsigned 63-bit integer. 
pub type u63be = u64;
/// Represents an unsigned 64-bit integer. 
pub type u64be = u64;
/// Represents an unsigned 9-bit integer. 
pub type u9le = u16;
/// Represents an unsigned 10-bit integer. 
pub type u10le = u16;
/// Represents an unsigned 11-bit integer. 
pub type u11le = u16;
/// Represents an unsigned 12-bit integer. 
pub type u12le = u16;
/// Represents an unsigned 13-bit integer. 
pub type u13le = u16;
/// Represents an unsigned 14-bit integer. 
pub type u14le = u16;
/// Represents an unsigned 15-bit integer. 
pub type u15le = u16;
/// Represents an unsigned 16-bit integer. 
pub type u16le = u16;
/// Represents an unsigned 17-bit integer. 
pub type u17le = u32;
/// Represents an unsigned 18-bit integer. 
pub type u18le = u32;
/// Represents an unsigned 19-bit integer. 
pub type u19le = u32;
/// Represents an unsigned 20-bit integer. 
pub type u20le = u32;
/// Represents an unsigned 21-bit integer. 
pub type u21le = u32;
/// Represents an unsigned 22-bit integer. 
pub type u22le = u32;
/// Represents an unsigned 23-bit integer. 
pub type u23le = u32;
/// Represents an unsigned 24-bit integer. 
pub type u24le = u32;
/// Represents an unsigned 25-bit integer. 
pub type u25le = u32;
/// Represents an unsigned 26-bit integer. 
pub type u26le = u32;
/// Represents an unsigned 27-bit integer. 
pub type u27le = u32;
/// Represents an unsigned 28-bit integer. 
pub type u28le = u32;
/// Represents an unsigned 29-bit integer. 
pub type u29le = u32;
/// Represents an unsigned 30-bit integer. 
pub type u30le = u32;
/// Represents an unsigned 31-bit integer. 
pub type u31le = u32;
/// Represents an unsigned 32-bit integer. 
pub type u32le = u32;
/// Represents an unsigned 33-bit integer. 
pub type u33le = u64;
/// Represents an unsigned 34-bit integer. 
pub type u34le = u64;

/// Represents an unsigned 35-bit integer. 
pub type u35le = u64;

/// Represents an unsigned 36-bit integer. 
pub type u36le = u64;
/// Represents an unsigned 37-bit integer. 
pub type u37le = u64;
/// Represents an unsigned 38-bit integer. 
pub type u38le = u64;
/// Represents an unsigned 39-bit integer. 
pub type u39le = u64;
/// Represents an unsigned 40-bit integer. 
pub type u40le = u64;
/// Represents an unsigned 41-bit integer. 
pub type u41le = u64;
/// Represents an unsigned 42-bit integer. 
pub type u42le = u64;
/// Represents an unsigned 43-bit integer. 
pub type u43le = u64;
/// Represents an unsigned 44-bit integer. 
pub type u44le = u64;
/// Represents an unsigned 45-bit integer. 
pub type u45le = u64;
/// Represents an unsigned 46-bit integer. 
pub type u46le = u64;
/// Represents an unsigned 47-bit integer. 
pub type u47le = u64;
/// Represents an unsigned 48-bit integer. 
pub type u48le = u64;
/// Represents an unsigned 49-bit integer. 
pub type u49le = u64;
/// Represents an unsigned 50-bit integer. 
pub type u50le = u64;
/// Represents an unsigned 51-bit integer. 
pub type u51le = u64;
/// Represents an unsigned 52-bit integer. 
pub type u52le = u64;
/// Represents an unsigned 53-bit integer. 
pub type u53le = u64;
/// Represents an unsigned 54-bit integer. 
pub type u54le = u64;
/// Represents an unsigned 55-bit integer. 
pub type u55le = u64;
/// Represents an unsigned 56-bit integer. 
pub type u56le = u64;
/// Represents an unsigned 57-bit integer. 
pub type u57le = u64;
/// Represents an unsigned 58-bit integer. 
pub type u58le = u64;
/// Represents an unsigned 59-bit integer. 
pub type u59le = u64;
/// Represents an unsigned 60-bit integer. 
pub type u60le = u64;
/// Represents an unsigned 61-bit integer. 
pub type u61le = u64;
/// Represents an unsigned 62-bit integer. 
pub type u62le = u64;
/// Represents an unsigned 63-bit integer. 
pub type u63le = u64;
/// Represents an unsigned 64-bit integer. 
pub type u64le = u64;
/// Represents an unsigned 9-bit integer in host endianness.
pub type u9he = u16;
/// Represents an unsigned 10-bit integer in host endianness.
pub type u10he = u16;
/// Represents an unsigned 11-bit integer in host endianness.
pub type u11he = u16;
/// Represents an unsigned 12-bit integer in host endianness.
pub type u12he = u16;
/// Represents an unsigned 13-bit integer in host endianness.
pub type u13he = u16;
/// Represents an unsigned 14-bit integer in host endianness.
pub type u14he = u16;
/// Represents an unsigned 15-bit integer in host endianness.
pub type u15he = u16;
/// Represents an unsigned 16-bit integer in host endianness.
pub type u16he = u16;
/// Represents an unsigned 17-bit integer in host endianness.
pub type u17he = u32;
/// Represents an unsigned 18-bit integer in host endianness.
pub type u18he = u32;
/// Represents an unsigned 19-bit integer in host endianness.
pub type u19he = u32;
/// Represents an unsigned 20-bit integer in host endianness.
pub type u20he = u32;
/// Represents an unsigned 21-bit integer in host endianness.
pub type u21he = u32;
/// Represents an unsigned 22-bit integer in host endianness.
pub type u22he = u32;
/// Represents an unsigned 23-bit integer in host endianness.
pub type u23he = u32;
/// Represents an unsigned 24-bit integer in host endianness.
pub type u24he = u32;
/// Represents an unsigned 25-bit integer in host endianness.
pub type u25he = u32;
/// Represents an unsigned 26-bit integer in host endianness.
pub type u26he = u32;
/// Represents an unsigned 27-bit integer in host endianness.
pub type u27he = u32;
/// Represents an unsigned 28-bit integer in host endianness.
pub type u28he = u32;
/// Represents an unsigned 29-bit integer in host endianness.
pub type u29he = u32;
/// Represents an unsigned 30-bit integer in host endianness.
pub type u30he = u32;
/// Represents an unsigned 31-bit integer in host endianness.
pub type u31he = u32;
/// Represents an unsigned 32-bit integer in host endianness.
pub type u32he = u32;
/// Represents an unsigned 33-bit integer in host endianness.
pub type u33he = u64;
/// Represents an unsigned 34-bit integer in host endianness.
pub type u34he = u64;
/// Represents an unsigned 35-bit integer in host endianness.
pub type u35he = u64;
/// Represents an unsigned 36-bit integer in host endianness.
pub type u36he = u64;
/// Represents an unsigned 37-bit integer in host endianness.
pub type u37he = u64;
/// Represents an unsigned 38-bit integer in host endianness.
pub type u38he = u64;
/// Represents an unsigned 39-bit integer in host endianness.
pub type u39he = u64;
/// Represents an unsigned 40-bit integer in host endianness.
pub type u40he = u64;
/// Represents an unsigned 41-bit integer in host endianness.
pub type u41he = u64;
/// Represents an unsigned 42-bit integer in host endianness.
pub type u42he = u64;
/// Represents an unsigned 43-bit integer in host endianness.
pub type u43he = u64;
/// Represents an unsigned 44-bit integer in host endianness.
pub type u44he = u64;
/// Represents an unsigned 45-bit integer in host endianness.
pub type u45he = u64;
/// Represents an unsigned 46-bit integer in host endianness.
pub type u46he = u64;
/// Represents an unsigned 47-bit integer in host endianness.
pub type u47he = u64;
/// Represents an unsigned 48-bit integer in host endianness.
pub type u48he = u64;
/// Represents an unsigned 49-bit integer in host endianness.
pub type u49he = u64;
/// Represents an unsigned 50-bit integer in host endianness.
pub type u50he = u64;
/// Represents an unsigned 51-bit integer in host endianness.
pub type u51he = u64;
/// Represents an unsigned 52-bit integer in host endianness.
pub type u52he = u64;
/// Represents an unsigned 53-bit integer in host endianness.
pub type u53he = u64;
/// Represents an unsigned 54-bit integer in host endianness.
pub type u54he = u64;
/// Represents an unsigned 55-bit integer in host endianness.
pub type u55he = u64;
/// Represents an unsigned 56-bit integer in host endianness.
pub type u56he = u64;
/// Represents an unsigned 57-bit integer in host endianness.
pub type u57he = u64;
/// Represents an unsigned 58-bit integer in host endianness.
pub type u58he = u64;
/// Represents an unsigned 59-bit integer in host endianness.
pub type u59he = u64;
/// Represents an unsigned 60-bit integer in host endianness.
pub type u60he = u64;
/// Represents an unsigned 61-bit integer in host endianness.
pub type u61he = u64;
/// Represents an unsigned 62-bit integer in host endianness.
pub type u62he = u64;
/// Represents an unsigned 63-bit integer in host endianness.
pub type u63he = u64;
/// Represents an unsigned 64-bit integer in host endianness.
pub type u64he = u64;

pub mod utils {

    pub fn u24be_from_bytes(bytes: [u8; 3]) -> super::u24be {
        (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2])
    }

    pub fn u24be_to_bytes(value: u32) -> [u8; 3] {
        [
            ((value >> 16) & 0xFF) as u8,
            ((value >> 8) & 0xFF) as u8,
            (value & 0xFF) as u8,
        ]
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn alias_sizes() {
        assert_eq!(std::mem::size_of::<u1>(), 1);
        assert_eq!(std::mem::size_of::<u12be>(), 2);
        assert_eq!(std::mem::size_of::<u24be>(), 4);
        assert_eq!(std::mem::size_of::<u64be>(), 8);
    }
}

