//! Laying out the SSH wire types beside codec's byte writer.

use codec::writer::ByteWriter;

/// Laying out the SSH wire types that are SSH's own (RFC 4251 section 5)
/// beside codec's [`ByteWriter`]: a `boolean`, a `string`, an `mpint` and a
/// `name-list`. A `byte`, a `uint32` and a `uint64` are the writer's own.
pub trait SshWrite {
    /// A `boolean`: one byte, zero or one.
    fn boolean(&mut self, value: bool) -> &mut Self;

    /// A `string`: a `uint32` length and that many bytes.
    ///
    /// # Panics
    /// Where `value` is longer than a `uint32` counts, four gibibytes, which
    /// no SSH packet carries.
    fn string(&mut self, value: &[u8]) -> &mut Self;

    /// An `mpint` of a non-negative integer, big-endian: its leading zero
    /// bytes dropped, a zero byte kept in front where the top bit would read
    /// as a sign, and zero written as the empty string.
    fn mpint(&mut self, magnitude: &[u8]) -> &mut Self;

    /// A `name-list`: the names comma-separated in one `string`.
    fn name_list(&mut self, names: &[&str]) -> &mut Self;
}

impl<W: ByteWriter> SshWrite for W {
    fn boolean(&mut self, value: bool) -> &mut Self {
        self.byte(u8::from(value))
    }

    fn string(&mut self, value: &[u8]) -> &mut Self {
        let length = u32::try_from(value.len()).expect("an SSH string of at most 4 GiB");
        self.u32_be(length).bytes(value)
    }

    fn mpint(&mut self, magnitude: &[u8]) -> &mut Self {
        let Some(start) = magnitude.iter().position(|byte| *byte != 0) else {
            return self.u32_be(0);
        };
        let trimmed = &magnitude[start..];
        if trimmed[0] & 0x80 == 0 {
            return self.string(trimmed);
        }
        let length = u32::try_from(trimmed.len() + 1).expect("an SSH mpint of at most 4 GiB");
        self.u32_be(length).byte(0).bytes(trimmed)
    }

    fn name_list(&mut self, names: &[&str]) -> &mut Self {
        self.string(names.join(",").as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_mpint_drops_leading_zeros_guards_its_sign_and_writes_zero_empty() {
        let mut small = Vec::new();
        small.mpint(&[0x00, 0x00, 0x0a, 0x0b]);
        let mut signed = Vec::new();
        signed.mpint(&[0x80, 0x01]);
        let mut zero = Vec::new();
        zero.mpint(&[0x00, 0x00]);

        assert_eq!(small, [0, 0, 0, 2, 0x0a, 0x0b]);
        assert_eq!(signed, [0, 0, 0, 3, 0x00, 0x80, 0x01]);
        assert_eq!(zero, [0, 0, 0, 0]);
    }

    #[test]
    fn a_boolean_is_one_byte_and_a_name_list_is_one_string() {
        let mut bytes = Vec::new();
        bytes.boolean(true).boolean(false).name_list(&["a", "b"]);

        assert_eq!(bytes, [1, 0, 0, 0, 0, 3, b'a', b',', b'b']);
    }
}
