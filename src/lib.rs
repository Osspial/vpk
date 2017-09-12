extern crate byteorder;

use std::str;
use std::io::{self, BufRead, Error, ErrorKind};

use byteorder::ReadBytesExt;

type VPKEndian = byteorder::LittleEndian;

#[derive(Debug, Default)]
pub struct DirEntry {
    pub file: String,
    pub crc: u32,
    pub preload_data: Vec<u8>,
    pub archive_index: Option<u16>,
    pub entry_offset: u32,
    pub entry_length: u32
}

/// `Read` to `Iterator` adapter that reads VPK directory trees.
pub struct DirReader<R: BufRead> {
    reader: R,
    path_buf: Vec<u8>,
    extn_len: usize,
    dir_len: usize,
    bytes_read: usize,
    header: DirHeader
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirHeader {
    tree_size: u32,
    header_v2: Option<DirHeader2>
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirHeader2 {
    file_data_section_size: u32,
    archive_md5_section_size: u32,
    other_md5_section_size: u32,
    signature_section_size: u32
}

impl<R: BufRead> DirReader<R> {
    /// Create a new VPK directory from a buffered read stream.
    pub fn new(mut reader: R) -> io::Result<DirReader<R>> {
        reader.read_u32::<VPKEndian>().and_then(|sig| if sig == 0x55aa1234 {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::InvalidData, format!("vpk file signature invalid; expected 0x55aa1234, found {}", sig)))
        })?;

        let version = reader.read_u32::<VPKEndian>().and_then(|version| match version {
            1  |
            2 => Ok(version),
            _ => Err(Error::new(ErrorKind::InvalidData, format!("vpk version unsupported; expected 1 or 2, found {}", version)))
        })?;

        let tree_size = reader.read_u32::<VPKEndian>()?;

        let header_v2 = match version {
            1 => None,
            2 => Some(DirHeader2 {
                file_data_section_size: reader.read_u32::<VPKEndian>()?,
                archive_md5_section_size: reader.read_u32::<VPKEndian>()?,
                other_md5_section_size: reader.read_u32::<VPKEndian>()?,
                signature_section_size: reader.read_u32::<VPKEndian>()?
            }),
            _ => unreachable!()
        };

        Ok(DirReader {
            reader,
            path_buf: Vec::new(),
            extn_len: 0,
            dir_len: 0,
            bytes_read: 0,
            header: DirHeader { tree_size, header_v2 }
        })
    }

    /// Get the size, in bytes, of the directory tree.
    #[inline]
    pub fn tree_size(&self) -> usize {
        self.header.tree_size as usize
    }

    /// Get the offset, in bytes, of the file data from the start of the file.
    #[inline]
    pub fn data_offset(&self) -> usize {
        // Tree size plus the header byte offset
        12 + 16 * self.header.header_v2.is_some() as usize + self.tree_size()
    }

    /// Length of the file data in the directory file. Comes after the directory tree.
    #[inline]
    pub fn data_len(&self) -> Option<usize> {
        self.header.header_v2.map(|h| h.file_data_section_size as usize)
    }
}

impl<R: BufRead> Iterator for DirReader<R> {
    type Item = io::Result<DirEntry>;
    fn next(&mut self) -> Option<io::Result<DirEntry>> {
        loop {
            match self.reader.read_until(0, &mut self.path_buf) {
                Ok(_) if self.bytes_read == self.header.tree_size as usize => return None,
                Ok(0) => return None,
                Ok(1) => {
                    self.bytes_read += 1;
                    if 0 < self.dir_len {
                        self.path_buf.truncate(self.extn_len);
                        self.dir_len = 0;
                    } else if 0 < self.extn_len {
                        self.path_buf.clear();
                        self.extn_len = 0;
                    } else if 0 == self.extn_len {
                        return None;
                    } else {
                        self.path_buf.truncate(self.extn_len + self.dir_len);
                    }
                },
                Ok(len) => {
                    self.bytes_read += len;
                    // Remove null terminator
                    let len = len - 1;
                    self.path_buf.pop();

                    if self.extn_len == 0 {
                        self.extn_len = len;
                    } else if self.dir_len == 0 {
                        self.dir_len = len;
                    } else {
                        let mut file_path = String::with_capacity(self.path_buf.len() + 2);
                        {
                            let buf_str = match str::from_utf8(&self.path_buf) {
                                Ok(ok) => ok,
                                Err(e) => return Some(Err(Error::new(ErrorKind::InvalidData, e)))
                            };
                            let path = &buf_str[self.extn_len..self.extn_len + self.dir_len];
                            let name = &buf_str[self.extn_len + self.dir_len..];
                            let extn = &buf_str[0..self.extn_len];

                            if path != " " {
                                file_path.push_str(&buf_str[self.extn_len..self.extn_len + self.dir_len]);
                                file_path.push('/');
                            }

                            if name != " " {
                                file_path.push_str(&buf_str[self.extn_len + self.dir_len..]);
                            }

                            if extn != " " {
                                file_path.push('.');
                                file_path.push_str(&buf_str[0..self.extn_len]);
                            }
                        }

                        macro_rules! try_io_result {
                            ($res:expr) => {{
                                match $res {
                                    Ok(ok) => ok,
                                    Err(e) => return Some(Err(e))
                                }
                            }}
                        }
                        let mut entry: DirEntry = DirEntry::default();
                        entry.file = file_path;
                        entry.crc = try_io_result!(self.reader.read_u32::<VPKEndian>());

                        let preload_bytes = try_io_result!(self.reader.read_u16::<VPKEndian>());

                        entry.archive_index = match try_io_result!(self.reader.read_u16::<VPKEndian>()) {
                            0x7fff => None,
                            archive_index => Some(archive_index)
                        };
                        entry.entry_offset = try_io_result!(self.reader.read_u32::<VPKEndian>());
                        entry.entry_length = try_io_result!(self.reader.read_u32::<VPKEndian>());

                        match try_io_result!(self.reader.read_u16::<VPKEndian>()) {
                            0xffff => (),
                            terminator => return Some(Err(Error::new(ErrorKind::InvalidData, format!("expected 0xffff, found 0x{:x}", terminator))))
                        }

                        entry.preload_data = vec![0; preload_bytes as usize];
                        match self.reader.read_exact(&mut entry.preload_data) {
                            Ok(()) => (),
                            Err(e) => return Some(Err(e))
                        }

                        self.bytes_read += preload_bytes as usize + (32 + 16 + 16 + 32 + 32 + 16) / 8;
                        self.path_buf.truncate(self.extn_len + self.dir_len);

                        return Some(Ok(entry))
                    }
                },
                Err(e) => return Some(Err(e))
            }
        }
    }
}
