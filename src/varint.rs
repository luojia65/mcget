//! An implementation of Minecraft's VarInt and VarLong types, focusing on
//! **minimal memory usage** and **maximum performance**.
//!
//! This module provides two structs, [`VarInt`] and [`VarLong`], and two pairs
//! of traits for type conversion and I/O: [`VarIntRead`] / [`VarLongRead`]
//! (reading) and [`VarIntWrite`] / [`VarLongWrite`] (writing). See the sections
//! below for details.
//!
//! The algorithms and structures follow the [wiki.vg protocol page][wiki].
//!
//! [wiki]: http://wiki.vg/Protocol#VarInt_and_VarLong
//!
//! # The VarInt and VarLong structs
//!
//! These two structs represent the two types mentioned above. The data they
//! store is guaranteed to be a valid VarInt / VarLong by their conversion
//! traits.
//!
//! You can create the structs with `VarInt::from(i32)` and
//! `VarLong::from(i64)`, and convert them back to plain values with
//! `i32::from(VarInt)` and `i64::from(VarLong)` for use in subsequent logic.
//!
//! Both structs implement `Default`, which makes them easier to use in code.
//!
//! # The two Read traits and the two Write traits
//!
//! They are [`VarIntRead`] / [`VarLongRead`] (reading) and [`VarIntWrite`] /
//! [`VarLongWrite`] (writing).
//!
//! Both Read traits are implemented for every `R` where `R: io::Read`, so you
//! can read `VarInt` and `VarLong` directly from IO streams such as network
//! connections or files.
//!
//! Likewise, both Write traits are implemented for every `W` where
//! `W: io::Write`, for convenience.
//!
//! # How this crate reduces memory usage
//!
//! Since only the [`VarInt`] and [`VarLong`] structs perform allocation, their
//! in-memory footprint must first be minimized. They store only fixed-size
//! integer data (rather than a pointer-plus-length combination), so memory
//! usage is kept to a minimum: [`VarInt`] takes 5 bytes and [`VarLong`] takes
//! 10.
//!
//! When writing to IO, reading from IO, or performing type conversions, this
//! crate allocates only a single `[u8; 1]` array as a buffer, which Rust
//! releases safely via ownership -- no GC needed. This saves memory during
//! computation and leaves more of it for network buffers, databases, and the
//! rest of your logic.

#![deny(missing_docs)]

use std::io;

macro_rules! var_impl {
    ($store_struct: ident, $read_trait: ident, $write_trait: ident, $read_func: ident, $write_func: ident,
    $conversation_type: ident, $size: expr, $error_too_long: expr) => {
        /// Struct representing a VarInt or VarLong.
        #[derive(Debug, Clone, Copy, Eq, PartialEq)]
        pub struct $store_struct {
            /// Fixed-size inner byte array storing the encoded VarInt / VarLong.
            inner: [u8; $size],
        }

        impl Default for $store_struct {
            fn default() -> Self {
                $store_struct {
                    inner: [0u8; $size],
                }
            }
        }

        /// The Read trait for this VarInt / VarLong struct.
        ///
        /// This trait is implemented for all `io::Read`.
        ///
        /// # Examples
        ///
        /// `Cursor` implements `io::Read`, and therefore also [`VarIntRead`]
        /// and [`VarLongRead`]:
        ///
        /// ```
        /// use mcping::varint::{VarInt, VarIntRead};
        /// use std::io::Cursor;
        ///
        /// fn main() {
        ///     // First create a Cursor.
        ///     let mut cur = Cursor::new(vec![0xff, 0xff, 0xff, 0xff, 0x07]);
        ///     // Then read a VarInt from the Cursor.
        ///     let var_int = cur.read_var_int().unwrap();
        ///     // var_int has the value 2147483647.
        ///     assert_eq!(var_int, VarInt::from(2147483647));
        /// }
        /// ```
        pub trait $read_trait {
            /// Reads a VarInt / VarLong from `self`.
            ///
            /// The current position is advanced by the length of the
            /// VarInt / VarLong.
            ///
            /// # Errors
            ///
            /// If the VarInt / VarLong to read is too long (invalid), or this
            /// function encounters any underlying I/O or other error, the
            /// corresponding error variant is returned.
            fn $read_func(&mut self) -> io::Result<$store_struct>;
        }

        impl<R> $read_trait for R
        where
            R: io::Read,
        {
            fn $read_func(&mut self) -> Result<$store_struct, io::Error> {
                let mut ans = $store_struct {
                    inner: [0u8; $size],
                };
                let mut ptr = 0;
                let mut buf = [0u8];
                loop {
                    self.read_exact(&mut buf)?;
                    if ptr >= $size {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, $error_too_long));
                    }
                    ans.inner[ptr] = buf[0];
                    ptr += 1;
                    if buf[0] & 0b1000_0000 == 0 {
                        return Ok(ans);
                    }
                }
            }
        }

        /// The Write trait for this VarInt / VarLong struct.
        ///
        /// This trait is implemented for all `io::Write`.
        ///
        /// # Examples
        ///
        /// `Cursor` implements `io::Write`, and therefore also [`VarIntWrite`]
        /// and [`VarLongWrite`]:
        ///
        /// ```
        /// use mcping::varint::{VarInt, VarIntWrite};
        /// use std::io::Cursor;
        ///
        /// fn main() {
        ///     // First create a Cursor and a VarInt.
        ///     let mut cur = Cursor::new(Vec::with_capacity(5));
        ///     let var_int = VarInt::from(2147483647);
        ///     // Then write it.
        ///     cur.write_var_int(var_int).unwrap();
        ///     // Now var_int has been written to cur.
        ///     assert_eq!(cur.into_inner(), vec![0xff, 0xff, 0xff, 0xff, 0x07]);
        /// }
        /// ```
        pub trait $write_trait {
            /// Writes a VarInt / VarLong to `self`.
            ///
            /// The current position is advanced by the length of the
            /// VarInt / VarLong.
            ///
            /// # Errors
            ///
            /// If this function encounters any underlying I/O or other error,
            /// the corresponding error variant is returned.
            fn $write_func(&mut self, n: $store_struct) -> io::Result<()>;
        }

        impl<W> $write_trait for W
        where
            W: io::Write,
        {
            fn $write_func(&mut self, n: $store_struct) -> io::Result<()> {
                let mut buf = [0x00];
                let mut ptr = 0;
                loop {
                    if n.inner[ptr] == 0 {
                        break;
                    }
                    buf[0] = n.inner[ptr];
                    self.write_all(&buf)?;
                    ptr += 1;
                    if ptr >= $size {
                        break;
                    }
                }
                // If nothing was written, the $store_struct equals 0.
                if ptr == 0 {
                    // At this point `buf` is still [0x00]; write it out.
                    self.write_all(&buf)?;
                }
                Ok(())
            }
        }

        impl From<$store_struct> for $conversation_type {
            fn from(v: $store_struct) -> Self {
                let mut ans = 0 as Self;
                let mut ptr = 0;
                loop {
                    let value = $conversation_type::from(v.inner[ptr] & 0b0111_1111);
                    ans |= value << (7 * ptr as Self);
                    if v.inner[ptr] & 0b1000_0000 == 0 {
                        return ans;
                    }
                    ptr += 1;
                }
            }
        }

        impl From<$conversation_type> for $store_struct {
            fn from(n: $conversation_type) -> Self {
                let mut ans = $store_struct {
                    inner: [0u8; $size],
                };
                let mut n = n;
                let mut ptr = 0;
                loop {
                    let mut tmp = (n & 0b0111_1111) as u8;
                    // Rust has no logical right-shift operator for unsigned types.
                    n = (n >> 7) & ($conversation_type::MAX >> 6);
                    if n != 0 {
                        tmp |= 0b1000_0000;
                    }
                    ans.inner[ptr] = tmp;
                    ptr += 1;
                    if n == 0 || ptr >= $size {
                        break;
                    }
                }
                ans
            }
        }
    };
}

var_impl!(
    VarInt,
    VarIntRead,
    VarIntWrite,
    read_var_int,
    write_var_int,
    i32,
    5,
    "varint too long (length > 5)"
);
var_impl!(
    VarLong,
    VarLongRead,
    VarLongWrite,
    read_var_long,
    write_var_long,
    i64,
    10,
    "varlong too long (length > 10)"
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_known_varint() {
        // Known case from wiki.vg.
        let mut cur = Cursor::new(vec![0xff, 0xff, 0xff, 0xff, 0x07]);
        let var_int = cur.read_var_int().unwrap();
        assert_eq!(var_int, VarInt::from(2147483647));
    }

    #[test]
    fn write_known_varint() {
        let mut cur = Cursor::new(Vec::with_capacity(5));
        let var_int = VarInt::from(2147483647);
        cur.write_var_int(var_int).unwrap();
        assert_eq!(cur.into_inner(), vec![0xff, 0xff, 0xff, 0xff, 0x07]);
    }

    #[test]
    fn roundtrip_varint() {
        let cases = [0i32, 1, 127, 128, 255, 2147483647, -1, -100, -2147483648];
        for &v in &cases {
            let vi = VarInt::from(v);
            let mut cur = Cursor::new(Vec::with_capacity(5));
            cur.write_var_int(vi).unwrap();
            let bytes = cur.into_inner();
            let mut reader = Cursor::new(bytes);
            let got = i32::from(reader.read_var_int().unwrap());
            assert_eq!(got, v, "roundtrip failed for value {v}");
        }
    }

    #[test]
    fn roundtrip_varlong() {
        let cases = [
            0i64,
            1,
            127,
            128,
            9223372036854775807,
            -1,
            -9223372036854775808,
        ];
        for &v in &cases {
            let vl = VarLong::from(v);
            let mut cur = Cursor::new(Vec::with_capacity(10));
            cur.write_var_long(vl).unwrap();
            let bytes = cur.into_inner();
            let mut reader = Cursor::new(bytes);
            let got = i64::from(reader.read_var_long().unwrap());
            assert_eq!(got, v, "roundtrip failed for value {v}");
        }
    }

    #[test]
    fn rejects_too_long_varint() {
        // 6 bytes all carrying the continuation bit -- an invalid VarInt.
        let mut cur = Cursor::new(vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x80]);
        assert!(cur.read_var_int().is_err());
    }

    #[test]
    fn zero_varint_writes_one_byte() {
        let mut cur = Cursor::new(Vec::with_capacity(5));
        cur.write_var_int(VarInt::from(0)).unwrap();
        assert_eq!(cur.into_inner(), vec![0x00]);
    }

    #[test]
    fn neg_one_is_five_bytes() {
        let mut cur = Cursor::new(Vec::with_capacity(5));
        cur.write_var_int(VarInt::from(-1)).unwrap();
        assert_eq!(cur.into_inner(), vec![0xff, 0xff, 0xff, 0xff, 0x0f]);
    }
}
