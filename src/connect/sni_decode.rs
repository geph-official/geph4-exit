use std::{
    cmp::min,
    io::{self, ErrorKind, Read},
};

use byteorder::{ByteOrder, NetworkEndian, ReadBytesExt};

pub fn decode_sni_from_start<R: Read>(mut reader: R) -> std::io::Result<String> {
    // skip the first 5 bytes (the header for the container containing the clienthello)
    for _ in 0..5 {
        reader.read_u8()?;
    }
    // Handshake message type.
    const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
    let typ = reader.read_u8()?;
    if typ != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "handshake message not a ClientHello (type {}, expected {})",
                typ, HANDSHAKE_TYPE_CLIENT_HELLO
            ),
        ));
    }

    // Handshake message length.
    let len = read_u24(&mut reader)?;
    let mut reader = reader.take(len.into());

    // ProtocolVersion (2 bytes) & random (32 bytes).
    skip(&mut reader, 34)?;

    // Session ID (u8-length vec), cipher suites (u16-length vec), compression methods (u8-length vec).
    skip_vec_u8(&mut reader)?;
    skip_vec_u16(&mut reader)?;
    skip_vec_u8(&mut reader)?;

    // Extensions.
    let ext_len = reader.read_u16::<NetworkEndian>()?;
    let new_limit = min(reader.limit(), ext_len.into());
    reader.set_limit(new_limit);
    loop {
        // Extension type & length.
        let ext_typ = reader.read_u16::<NetworkEndian>()?;
        let ext_len = reader.read_u16::<NetworkEndian>()?;

        const EXTENSION_TYPE_SNI: u16 = 0;
        if ext_typ != EXTENSION_TYPE_SNI {
            skip(&mut reader, ext_len.into())?;
            continue;
        }
        let new_limit = min(reader.limit(), ext_len.into());
        reader.set_limit(new_limit);

        // ServerNameList length.
        let snl_len = reader.read_u16::<NetworkEndian>()?;
        let new_limit = min(reader.limit(), snl_len.into());
        reader.set_limit(new_limit);

        // ServerNameList.
        loop {
            // NameType & length.
            let name_typ = reader.read_u8()?;

            const NAME_TYPE_HOST_NAME: u8 = 0;
            if name_typ != NAME_TYPE_HOST_NAME {
                skip_vec_u16(&mut reader)?;
                continue;
            }

            let name_len = reader.read_u16::<NetworkEndian>()?;
            let new_limit = min(reader.limit(), name_len.into());
            reader.set_limit(new_limit);
            let mut name_buf = vec![0; name_len.into()];
            reader.read_exact(&mut name_buf)?;
            return String::from_utf8(name_buf)
                .map_err(|err| io::Error::new(ErrorKind::InvalidData, err));
        }
    }
}

fn skip<R: Read>(reader: R, len: u64) -> io::Result<()> {
    let bytes_read = std::io::copy(&mut reader.take(len), &mut std::io::sink())?;
    if bytes_read < len {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            format!("skip read {} < {} bytes", bytes_read, len),
        ));
    }
    Ok(())
}

fn skip_vec_u8<R: Read>(mut reader: R) -> io::Result<()> {
    let sz = reader.read_u8()?;
    skip(reader, sz.into())
}

fn skip_vec_u16<R: Read>(mut reader: R) -> io::Result<()> {
    let sz = reader.read_u16::<NetworkEndian>()?;
    skip(reader, sz.into())
}

fn read_u24<R: Read>(mut reader: R) -> io::Result<u32> {
    let mut buf = [0; 3];
    reader
        .read_exact(&mut buf)
        .map(|_| NetworkEndian::read_u24(&buf))
}
