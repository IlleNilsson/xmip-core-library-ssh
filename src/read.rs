//! Reading the SSH wire types off codec's cursor.

use codec::cursor::Cursor;
use codec::{CodecError, Result};

/// Reading the SSH wire types that are SSH's own (RFC 4251 section 5) off
/// codec's [`Cursor`]; a `byte`, a `uint32` and a `uint64` are codec's
/// `byte`, `u32_be` and `u64_be`.
pub trait SshRead<'a> {
    /// A `boolean`: one byte, and anything but zero is true.
    ///
    /// # Errors
    /// Where nothing is left.
    fn boolean(&mut self) -> Result<bool>;

    /// A `string`: a `uint32` length and that many bytes, borrowed.
    ///
    /// # Errors
    /// Where the length or the bytes it promises are not there.
    fn string(&mut self) -> Result<&'a [u8]>;

    /// A `string` that is text, such as an algorithm or a user name.
    ///
    /// # Errors
    /// Where the string is not there or is not UTF-8.
    fn text(&mut self) -> Result<&'a str>;

    /// A positive `mpint`, without its leading zero bytes: the integers of
    /// a key or a signature, big-endian.
    ///
    /// # Errors
    /// Where the string is not there, or the integer is negative.
    fn mpint(&mut self) -> Result<&'a [u8]>;

    /// A `name-list`: comma-separated names in one `string`, none of them
    /// empty; an empty string is an empty list.
    ///
    /// # Errors
    /// Where the string is not there, is not text, or names an empty name.
    fn name_list(&mut self) -> Result<Vec<&'a str>>;
}

impl<'a> SshRead<'a> for Cursor<'a> {
    fn boolean(&mut self) -> Result<bool> {
        Ok(self.byte()? != 0)
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let length = usize::try_from(self.u32_be()?).unwrap_or(usize::MAX);
        self.take(length)
    }

    fn text(&mut self) -> Result<&'a str> {
        core::str::from_utf8(self.string()?)
            .map_err(|_| CodecError::new("an SSH string that should be text is not UTF-8"))
    }

    fn mpint(&mut self) -> Result<&'a [u8]> {
        let value = self.string()?;
        if value.first().is_some_and(|first| first & 0x80 != 0) {
            return Err(CodecError::new(
                "an SSH mpint holds a negative integer where a positive one belongs",
            ));
        }
        let zeros = value.iter().take_while(|byte| **byte == 0).count();
        Ok(&value[zeros..])
    }

    fn name_list(&mut self) -> Result<Vec<&'a str>> {
        let names = self.text()?;
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let list: Vec<&str> = names.split(',').collect();
        if list.iter().any(|name| name.is_empty()) {
            return Err(CodecError::new(format!(
                "the SSH name-list '{names}' holds an empty name"
            )));
        }
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SshWrite;
    use codec::writer::ByteWriter;

    #[test]
    fn a_message_reads_back_the_types_it_was_written_with() {
        let mut bytes = Vec::new();
        bytes
            .byte(20)
            .boolean(true)
            .u32_be(0x0102_0304)
            .string(b"ssh-connection")
            .u64_be(0x1122_3344_5566_7788)
            .mpint(&[0x00, 0x80, 0x01])
            .name_list(&["curve25519-sha256", "ecdh-sha2-nistp256"]);
        let mut reader = Cursor::new(&bytes);

        assert_eq!(reader.byte().expect("byte"), 20);
        assert!(reader.boolean().expect("boolean"));
        assert_eq!(reader.u32_be().expect("uint32"), 0x0102_0304);
        assert_eq!(reader.text().expect("text"), "ssh-connection");
        assert_eq!(reader.u64_be().expect("uint64"), 0x1122_3344_5566_7788);
        assert_eq!(reader.mpint().expect("mpint"), [0x80, 0x01]);
        assert_eq!(
            reader.name_list().expect("name-list"),
            ["curve25519-sha256", "ecdh-sha2-nistp256"]
        );
        assert!(reader.is_empty());
    }

    #[test]
    fn a_string_that_promises_more_than_there_is_is_refused() {
        let bytes = [0x00, 0x00, 0x00, 0x08, 0x01, 0x02];

        let error = Cursor::new(&bytes).string().expect_err("short");

        assert!(error.message.contains("runs past the end"), "{error}");
        assert!(Cursor::new(&[0x00, 0x00]).string().is_err());
    }

    #[test]
    fn a_negative_mpint_and_text_that_is_not_utf8_are_refused() {
        let mut negative = Vec::new();
        negative.string(&[0x80, 0x01]);
        let mut binary = Vec::new();
        binary.string(&[0xff, 0xfe]);

        let sign = Cursor::new(&negative).mpint().expect_err("negative");
        let text = Cursor::new(&binary).text().expect_err("not text");

        assert!(sign.message.contains("negative"), "{sign}");
        assert!(text.message.contains("UTF-8"), "{text}");
    }

    #[test]
    fn an_empty_name_list_is_empty_and_an_empty_name_is_refused() {
        let mut empty = Vec::new();
        empty.string(b"");
        let mut hole = Vec::new();
        hole.string(b"aes256-ctr,,aes128-ctr");

        assert!(Cursor::new(&empty).name_list().expect("empty").is_empty());
        let error = Cursor::new(&hole).name_list().expect_err("a hole");
        assert!(error.message.contains("empty name"), "{error}");
    }
}
