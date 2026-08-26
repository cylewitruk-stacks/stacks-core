// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Canonical offset-directory framing for variable-width children.
//!
//! A directory stores an offset-width code, followed by `child_count + 1` little-endian offsets
//! and a contiguous child-data region. The first and final offsets delimit the entire data region;
//! adjacent offsets delimit one child. Canonical records always use the narrowest width capable of
//! addressing the data region.

use super::PackedValueError;

/// Width of each offset in a packed directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum OffsetWidth {
    /// One-byte offsets for data regions no larger than 255 bytes.
    U8 = 0,
    /// Two-byte offsets for data regions no larger than 65,535 bytes.
    U16 = 1,
    /// Four-byte offsets for larger bounded Clarity values.
    U32 = 2,
}

impl OffsetWidth {
    /// Select the narrowest offset width that can address the complete child-data region.
    fn for_data_len(data_len: usize) -> Self {
        if data_len <= u8::MAX as usize {
            Self::U8
        } else if data_len <= u16::MAX as usize {
            Self::U16
        } else {
            Self::U32
        }
    }

    /// Decode a wire-format width tag.
    fn from_code(code: u8) -> Result<Self, PackedValueError> {
        match code {
            0 => Ok(Self::U8),
            1 => Ok(Self::U16),
            2 => Ok(Self::U32),
            _ => Err(PackedValueError::InvalidRecord("invalid offset-width code")),
        }
    }

    /// Return the number of bytes occupied by one offset.
    const fn byte_len(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U32 => 4,
        }
    }

    /// Decode one offset encoded at this width.
    fn read(self, bytes: &[u8]) -> Result<usize, PackedValueError> {
        match (self, bytes) {
            (Self::U8, [value]) => Ok(usize::from(*value)),
            (Self::U16, [first, second]) => Ok(usize::from(u16::from_le_bytes([*first, *second]))),
            (Self::U32, [first, second, third, fourth]) => {
                usize::try_from(u32::from_le_bytes([*first, *second, *third, *fourth]))
                    .map_err(|_| PackedValueError::SizeOverflow)
            }
            _ => Err(PackedValueError::InvalidRecord(
                "invalid encoded offset width",
            )),
        }
    }

    /// Encode one offset into an exactly sized target slice.
    fn write(self, target: &mut [u8], value: usize) -> Result<(), PackedValueError> {
        match (self, target) {
            (Self::U8, [byte]) => {
                *byte = u8::try_from(value).map_err(|_| PackedValueError::SizeOverflow)?;
            }
            (Self::U16, bytes @ [_, _]) => bytes.copy_from_slice(
                &u16::try_from(value)
                    .map_err(|_| PackedValueError::SizeOverflow)?
                    .to_le_bytes(),
            ),
            (Self::U32, bytes @ [_, _, _, _]) => bytes.copy_from_slice(
                &u32::try_from(value)
                    .map_err(|_| PackedValueError::SizeOverflow)?
                    .to_le_bytes(),
            ),
            _ => {
                return Err(PackedValueError::InvalidRecord(
                    "invalid encoded offset width",
                ));
            }
        }
        Ok(())
    }
}

/// Return the canonical directory plus child-data length.
pub fn directory_total_len(count: usize, data_len: usize) -> Result<usize, PackedValueError> {
    directory_header_len(count, OffsetWidth::for_data_len(data_len))?
        .checked_add(data_len)
        .ok_or(PackedValueError::SizeOverflow)
}

/// Return the bytes required by the `count + 1` directory offsets.
fn offset_table_len(count: usize, width: OffsetWidth) -> Result<usize, PackedValueError> {
    count
        .checked_add(1)
        .and_then(|count| count.checked_mul(width.byte_len()))
        .ok_or(PackedValueError::SizeOverflow)
}

/// Return the width tag plus offset-table length for a directory.
fn directory_header_len(count: usize, width: OffsetWidth) -> Result<usize, PackedValueError> {
    offset_table_len(count, width)?
        .checked_add(1)
        .ok_or(PackedValueError::SizeOverflow)
}

/// A temporary 32-bit directory that permits one-pass child encoding.
///
/// The encoder does not know the final child-data length up front. It reserves the widest directory,
/// writes offsets as children are appended, then compacts to the canonical minimal width.
pub struct WideDirectory {
    /// Byte position of the temporary directory's width tag.
    start: usize,
    /// Byte position where encoded child bodies begin.
    data_start: usize,
    /// Number of framed child bodies.
    count: usize,
}

/// Reserve a temporary 32-bit directory at the current output position.
pub fn reserve_wide_directory(
    count: usize,
    output: &mut Vec<u8>,
) -> Result<WideDirectory, PackedValueError> {
    let start = output.len();
    let directory_len = directory_header_len(count, OffsetWidth::U32)?;
    let data_start = start
        .checked_add(directory_len)
        .ok_or(PackedValueError::SizeOverflow)?;
    output.resize(data_start, 0);
    Ok(WideDirectory {
        start,
        data_start,
        count,
    })
}

impl WideDirectory {
    /// Record the current child-data length at one directory index.
    pub fn write_wide_offset(
        &self,
        output: &mut [u8],
        index: usize,
    ) -> Result<(), PackedValueError> {
        let offset = output
            .len()
            .checked_sub(self.data_start)
            .ok_or(PackedValueError::SizeOverflow)?;
        let offsets_start = self
            .start
            .checked_add(1)
            .ok_or(PackedValueError::SizeOverflow)?;
        write_offset(output, offsets_start, OffsetWidth::U32, index, offset)
    }

    /// Rewrite this directory to its canonical narrowest offset width.
    pub fn compact(self, output: &mut Vec<u8>) -> Result<(), PackedValueError> {
        let end = output.len();
        let data_len = end
            .checked_sub(self.data_start)
            .ok_or(PackedValueError::SizeOverflow)?;
        let compact_width = OffsetWidth::for_data_len(data_len);
        *output
            .get_mut(self.start)
            .ok_or(PackedValueError::SizeOverflow)? = compact_width as u8;
        let offsets_start = self
            .start
            .checked_add(1)
            .ok_or(PackedValueError::SizeOverflow)?;
        for index in 0..=self.count {
            let source = index
                .checked_mul(OffsetWidth::U32.byte_len())
                .and_then(|offset| offsets_start.checked_add(offset))
                .ok_or(PackedValueError::SizeOverflow)?;
            let source_end = source
                .checked_add(OffsetWidth::U32.byte_len())
                .ok_or(PackedValueError::SizeOverflow)?;
            let value = OffsetWidth::U32.read(
                output
                    .get(source..source_end)
                    .ok_or(PackedValueError::SizeOverflow)?,
            )?;
            write_offset(output, offsets_start, compact_width, index, value)?;
        }
        let compact_data_start = self
            .start
            .checked_add(directory_header_len(self.count, compact_width)?)
            .ok_or(PackedValueError::SizeOverflow)?;
        output.copy_within(self.data_start..end, compact_data_start);
        output.truncate(
            compact_data_start
                .checked_add(data_len)
                .ok_or(PackedValueError::SizeOverflow)?,
        );
        Ok(())
    }
}

/// Write one indexed offset into a directory embedded in `output`.
fn write_offset(
    output: &mut [u8],
    directory_start: usize,
    width: OffsetWidth,
    index: usize,
    value: usize,
) -> Result<(), PackedValueError> {
    let byte_width = width.byte_len();
    let start = directory_start
        .checked_add(
            index
                .checked_mul(byte_width)
                .ok_or(PackedValueError::SizeOverflow)?,
        )
        .ok_or(PackedValueError::SizeOverflow)?;
    let end = start
        .checked_add(byte_width)
        .ok_or(PackedValueError::SizeOverflow)?;
    let target = output
        .get_mut(start..end)
        .ok_or(PackedValueError::SizeOverflow)?;
    width.write(target, value)
}

/// A borrowed view over packed directory framing and validated endpoints.
pub struct Directory<'a> {
    /// Contiguous encoded offset table, excluding the width tag.
    offsets: &'a [u8],
    /// Contiguous child-body region addressed by `offsets`.
    data: &'a [u8],
    /// Canonical width shared by all encoded offsets.
    width: OffsetWidth,
    /// Number of child bodies represented by the directory.
    count: usize,
}

impl<'a> Directory<'a> {
    /// Parse canonical directory framing and validate its fixed endpoints.
    ///
    /// [`Directory::children`] validates every intermediate boundary while consuming the children,
    /// avoiding a second offset-table scan on successful decode and reconstruction paths.
    pub fn parse(bytes: &'a [u8], count: usize) -> Result<Self, PackedValueError> {
        let (&code, rest) = bytes
            .split_first()
            .ok_or(PackedValueError::InvalidRecord("missing offset-width code"))?;
        let width = OffsetWidth::from_code(code)?;
        let offset_len = offset_table_len(count, width)?;
        let (offsets, data) =
            rest.split_at_checked(offset_len)
                .ok_or(PackedValueError::InvalidRecord(
                    "truncated offset directory",
                ))?;
        if width != OffsetWidth::for_data_len(data.len()) {
            return Err(PackedValueError::InvalidRecord("non-minimal offset width"));
        }
        let directory = Self {
            offsets,
            data,
            width,
            count,
        };
        if directory.offset(0)? != 0 || directory.offset(count)? != data.len() {
            return Err(PackedValueError::InvalidRecord(
                "invalid directory endpoints",
            ));
        }
        Ok(directory)
    }

    /// Decode one validated offset-table entry.
    fn offset(&self, index: usize) -> Result<usize, PackedValueError> {
        if index > self.count {
            return Err(PackedValueError::InvalidRecord(
                "directory index out of bounds",
            ));
        }
        let width = self.width.byte_len();
        let start = index
            .checked_mul(width)
            .ok_or(PackedValueError::SizeOverflow)?;
        let end = start
            .checked_add(width)
            .ok_or(PackedValueError::SizeOverflow)?;
        self.width.read(
            self.offsets
                .get(start..end)
                .ok_or(PackedValueError::InvalidRecord(
                    "truncated offset directory",
                ))?,
        )
    }

    /// Iterate through every child while validating each offset exactly once.
    pub fn children(&self) -> DirectoryChildren<'_, 'a> {
        DirectoryChildren {
            directory: self,
            index: 0,
            previous: 0,
        }
    }
}

/// Forward iterator that validates directory ordering while yielding child slices.
pub struct DirectoryChildren<'directory, 'bytes> {
    /// Borrowed validated directory framing.
    directory: &'directory Directory<'bytes>,
    /// Index of the next child body.
    index: usize,
    /// Start offset of the next child body.
    previous: usize,
}

impl<'bytes> Iterator for DirectoryChildren<'_, 'bytes> {
    type Item = Result<&'bytes [u8], PackedValueError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.directory.count {
            return None;
        }
        let end = if self.index + 1 == self.directory.count {
            self.directory.data.len()
        } else {
            match self.directory.offset(self.index + 1) {
                Ok(offset) => offset,
                Err(error) => {
                    self.index = self.directory.count;
                    return Some(Err(error));
                }
            }
        };
        if end < self.previous || end > self.directory.data.len() {
            self.index = self.directory.count;
            return Some(Err(PackedValueError::InvalidRecord(
                "invalid directory ordering",
            )));
        }
        let child = self
            .directory
            .data
            .get(self.previous..end)
            .ok_or(PackedValueError::InvalidRecord("invalid child offsets"));
        self.previous = end;
        self.index += 1;
        Some(child)
    }
}

#[cfg(test)]
mod tests {
    use super::{Directory, OffsetWidth};

    #[test]
    fn offset_width_changes_at_integer_boundaries() {
        assert_eq!(OffsetWidth::for_data_len(0), OffsetWidth::U8);
        assert_eq!(OffsetWidth::for_data_len(u8::MAX as usize), OffsetWidth::U8);
        assert_eq!(
            OffsetWidth::for_data_len(u8::MAX as usize + 1),
            OffsetWidth::U16
        );
        assert_eq!(
            OffsetWidth::for_data_len(u16::MAX as usize),
            OffsetWidth::U16
        );
        assert_eq!(
            OffsetWidth::for_data_len(u16::MAX as usize + 1),
            OffsetWidth::U32
        );
    }

    #[test]
    fn child_iteration_validates_each_boundary_once() {
        let valid = [0, 0, 1, 2, 0xaa, 0xbb];
        let directory = Directory::parse(&valid, 2).unwrap();
        let children = directory.children().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(children, [&[0xaa][..], &[0xbb][..]]);

        let invalid = [0, 0, 2, 1, 0xaa];
        let directory = Directory::parse(&invalid, 2).unwrap();
        assert!(directory.children().next().unwrap().is_err());

        let descending = [0, 0, 1, 0, 1, 0xaa];
        let directory = Directory::parse(&descending, 3).unwrap();
        let mut children = directory.children();
        assert_eq!(children.next().unwrap().unwrap(), &[0xaa]);
        assert!(children.next().unwrap().is_err());
    }
}
