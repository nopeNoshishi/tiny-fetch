use std::collections::HashMap;
use std::io::{stdin, BufReader, Read, Write};

use anyhow::{Context, Result};
use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};

const MSB_BIT_MASK: u8 = 0b1000_0000;
const TYPE_BIT_MASK: u8 = 0b0111_0000;
const SIZE_BITS: usize = 7;

#[derive(Debug, PartialEq)]
pub enum PackObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl From<u8> for PackObjectType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Commit,
            2 => Self::Tree,
            3 => Self::Blob,
            4 => Self::Tag,
            6 => Self::OfsDelta,
            7 => Self::RefDelta,
            _ => unreachable!(),
        }
    }
}

impl PackObjectType {
    fn as_str(&self) -> &str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
            _ => "[no type]",
        }
    }
}

fn read_bytes<R: Read, const N: usize>(reader: &mut R, buffer: &mut [u8; N]) -> Result<()> {
    reader.read_exact(buffer)?;
    Ok(())
}

fn read_header<R: Read>(pack: &mut R) -> Result<(String, u32, u32)> {
    // 全てのメタデータは 4 bytes
    let mut buffer = [0; 4];

    read_bytes(pack, &mut buffer)?;
    let signature = String::from_utf8(buffer.to_vec())?;

    read_bytes(pack, &mut buffer)?;
    let version = u32::from_be_bytes(buffer);

    read_bytes(pack, &mut buffer)?;
    let entries = u32::from_be_bytes(buffer);

    Ok((signature, version, entries))
}

fn read_type_and_size<R: Read>(pack: &mut R) -> Result<(bool, PackObjectType, u8)> {
    const BITS: u8 = 4;

    let mut buffer = [0; 1];
    read_bytes(pack, &mut buffer)?;
    let is_continue = buffer[0] & MSB_BIT_MASK != 0;
    let obj_type = ((buffer[0] & TYPE_BIT_MASK) >> BITS).into();
    let size = buffer[0] & 0b0000_1111;

    Ok((is_continue, obj_type, size))
}

fn read_size_bits<R: Read>(pack: &mut R) -> Result<(bool, u8)> {
    let mut buffer = [0; 1];
    read_bytes(pack, &mut buffer)?;
    let is_continue = buffer[0] & MSB_BIT_MASK != 0;
    let size = buffer[0] & !MSB_BIT_MASK;

    Ok((is_continue, size))
}

fn read_size<R: Read>(pack: &mut R) -> Result<usize> {
    let mut size: usize = 0;
    let mut shift = 0;
    loop {
        let (is_continue, value) = read_size_bits(pack)?;

        size += (value as usize) << shift;
        // Stop if this is the last byte
        if !is_continue {
            return Ok(size);
        }

        shift += SIZE_BITS;
    }
}

fn read_compressed_data<R: Read>(pack: &mut R, content_size: usize) -> Result<(Vec<u8>, u64, u64)> {
    let mut compressed_data = Vec::new();
    let mut buffer = [0; 1];

    loop {
        read_bytes(pack, &mut buffer)?;
        compressed_data.write_all(&buffer)?;

        let mut decompressed_data = Vec::new();
        let mut decoder = ZlibDecoder::new(&compressed_data[..]);
        let res = decoder.read_to_end(&mut decompressed_data);

        let total_in = decoder.total_in();
        let total_out = decoder.total_out();

        if res.is_ok() && total_out == content_size as u64 {
            return Ok((decompressed_data, total_in, total_out));
        }
    }
}

fn read_hash<R: Read>(pack: &mut R) -> Result<String> {
    let mut buffer = [0; 20];
    read_bytes(pack, &mut buffer)?;

    Ok(hex::encode(buffer))
}

fn read_copy_instruction_offset_and_size<R: Read>(
    mut instruction: u8,
    instructions: &mut R,
) -> Result<(usize, usize)> {
    let mut offset = 0;
    for index in 0..4 {
        if instruction & 0b0000_0001 != 0 {
            let mut buffer = [0; 1];
            read_bytes(instructions, &mut buffer)?;
            offset |= (buffer[0] as usize) << (index * 8);
        }
        instruction >>= 1;
    }

    let mut size = 0;
    for index in 0..3 {
        if instruction & 0b0000_0001 != 0 {
            let mut buffer = [0; 1];
            read_bytes(instructions, &mut buffer)?;
            size |= (buffer[0] as usize) << (index * 8);
        }
        instruction >>= 1;
    }
    if size == 0 {
        size = 0x10000_usize
    }

    Ok((offset, size))
}

fn hash(obj_type: &PackObjectType, content: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(format!("{} {}\0", obj_type.as_str(), content.len()));
    hasher.update(content);

    let hash = hasher.finalize();
    hex::encode(hash)
}

fn reconstruct(mut delta_data: &[u8], base_content: &[u8]) -> Result<Vec<u8>> {
    let _base_size = read_size(&mut delta_data)?;
    let _reconstruct_size = read_size(&mut delta_data)?;

    let mut reconstruct_content = Vec::new();
    loop {
        let mut instruction = [0; 1];
        // end of instruction
        if read_bytes(&mut delta_data, &mut instruction).is_err() {
            break;
        }

        // Insert Instruction
        if instruction[0] & 0b1000_0000 == 0 {
            let add_size = instruction[0];

            let mut data = vec![0; add_size as usize];
            delta_data.read_exact(&mut data)?;
            reconstruct_content.extend(data);

        // Copy Instruction
        } else {
            let (offset, size) =
                read_copy_instruction_offset_and_size(instruction[0], &mut delta_data)?;
            let copy_data = base_content.get(offset..(offset + size)).unwrap();
            reconstruct_content.extend_from_slice(copy_data);
        }
    }

    Ok(reconstruct_content)
}

fn main() -> Result<()> {
    let stdio = stdin();
    let mut pack = BufReader::new(stdio);

    let (signature, version, entries) = read_header(&mut pack)?;
    println!("signature: {signature}\nversion: {version}\nentries: {entries}");

    let mut stores = HashMap::<String, (Vec<u8>, PackObjectType)>::new();
    for _ in 0..entries {
        let mut content_size = 0_usize;
        let (is_continue, obj_type, first_size) = read_type_and_size(&mut pack)?;
        content_size += first_size as usize;

        if is_continue {
            let size = read_size(&mut pack)?;
            content_size += size << 4;
        }
        println!("object type: {obj_type:?}\ncontent size: {content_size}");

        match obj_type {
            PackObjectType::RefDelta => {
                let base_hash = read_hash(&mut pack)?;
                println!("base object hash: {base_hash}");

                let (delta_data, _, _) = read_compressed_data(&mut pack, content_size)?;
                let (base_content, obj_type) = stores
                    .get(&base_hash)
                    .context("failed to get base content")?;

                let reconstruct_content = reconstruct(&delta_data, base_content)?;
                let hash = hash(obj_type, &reconstruct_content);
                println!(
                    "obj hash: {hash}\ncompressed size: None\ncontent size: {}",
                    reconstruct_content.len()
                );
            }
            PackObjectType::OfsDelta => {}
            _ => {
                let (content, total_in, total_out) = read_compressed_data(&mut pack, content_size)?;
                let hash = hash(&obj_type, &content);
                stores.insert(hash.clone(), (content, obj_type));
                println!(
                    "obj hash: {hash}\ncompressed size: {total_in}\ncontent size: {total_out}"
                );
            }
        }
    }

    Ok(())
}
