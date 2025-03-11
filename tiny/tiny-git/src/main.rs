use std::collections::HashMap;
use std::io::Read;
use std::io::{stdin, stdout, BufReader, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};

use anyhow::{bail, Context as _, Result};
use clap::{Parser, Subcommand};
use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};
use ssh2::Session;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct TinyGit {
    #[clap(subcommand)]
    sub: TinyGitSubcommand,

    #[arg(short = 'H', long, default_value = "localhost")]
    host: String,

    #[arg(short, long, default_value_t = 50022)]
    port: u64,

    #[arg(short, long, default_value = "root")]
    username: String,

    #[arg(short = 'P', long, default_value = "password")]
    password: String,
}

#[derive(Debug, Subcommand)]
enum TinyGitSubcommand {
    Push {
        #[arg(short, long)]
        revision: String,
    },
    Pull {
        #[arg(short, long)]
        revision: String,
    },
    Unpack,
    Pack {
        #[arg(short, long)]
        revision: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
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

fn main() -> Result<()> {
    let cli = TinyGit::parse();

    match &cli.sub {
        TinyGitSubcommand::Pack { revision } => {
            let packed = pack(revision.clone())?;
            let mut stdout = stdout();
            stdout.write_all(&packed)?;
            stdout.flush()?;
        }
        TinyGitSubcommand::Unpack => {
            let stdio = stdin();
            let entries = unpack(stdio)?;

            // 簡易的に書き込んだことにする
            let mut fs = std::fs::File::create("success.txt")?;
            for (hash, (content, obj_type)) in entries.into_iter() {
                fs.write_all(
                    format!("{}: {} {}\n", obj_type.as_str(), hash, content.len()).as_bytes(),
                )?;
            }
            fs.flush()?;
        }
        TinyGitSubcommand::Push { revision } => {
            let ssh = ssh(cli.username, cli.password, cli.host, cli.port)?;

            // `packed data` を取得
            let packed = pack(revision.clone())?;

            // チャンネルを生成してサーバーでコマンドを実行し、プロセスの入力を渡す
            let mut channel = ssh.channel_session()?;
            channel.exec("./tiny-git unpack")?;
            channel.write_all(&packed)?;
            channel.flush()?;

            // サーバーのプロセス出力を受け取っておく
            let mut s = Vec::new();
            channel.read_to_end(&mut s)?;
        }
        TinyGitSubcommand::Pull { revision } => {
            let ssh = ssh(cli.username, cli.password, cli.host, cli.port)?;

            // チャンネルを生成してサーバーでコマンドを実行し、プロセスの出力を取得する
            let mut channel = ssh.channel_session()?;
            channel.exec(&format!("./tiny-git pack --revision {}", revision))?;
            let mut packed = Vec::new();
            channel.read_to_end(&mut packed)?;

            // 取得した `packed data` を `unpack`
            let entries = unpack(&packed[..])?;

            // 簡易的に読み込んだことにする
            let mut fs = std::fs::File::create("success.txt")?;
            for (hash, (content, obj_type)) in entries.into_iter() {
                fs.write_all(
                    format!("{}: {} {}\n", obj_type.as_str(), hash, content.len()).as_bytes(),
                )?;
            }
            fs.flush()?;
        }
    }

    Ok(())
}

fn ssh(username: String, password: String, host: String, port: u64) -> Result<Session> {
    let tcp = TcpStream::connect(format!("{host}:{port}"))?;
    let mut session = Session::new()?;

    session.set_tcp_stream(tcp);
    session.handshake()?;
    session.userauth_password(&username, &password)?;

    if !session.authenticated() {
        bail!("no authenticated in ssh");
    }

    Ok(session)
}

fn pack(revision: String) -> Result<Vec<u8>> {
    let mut child = Command::new("git")
        .args(["pack-objects", "--stdout", "--revs", "-q"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let stdin = child.stdin.as_mut().expect("no stdin");
    stdin.write_all(revision.as_bytes())?;
    stdin.flush()?;

    child.wait()?;
    let mut output = Vec::new();
    let stdout = child.stdout.as_mut().expect("no stdout");
    stdout.read_to_end(&mut output)?;

    Ok(output)
}

const MSB_BIT_MASK: u8 = 0b1000_0000;
const TYPE_BIT_MASK: u8 = 0b0111_0000;
const SIZE_BITS: usize = 7;

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

    // 下位 4 ビットが offset のバイト数を示す。
    // ビットが立っている場合だけ 1 バイトを読み込み、(index*8) ビット左にシフトして offset に格納する。
    for index in 0..4 {
        // もし最下位ビットが 1 なら、この offset のバイトが存在するということ
        if instruction & 0b0000_0001 != 0 {
            let mut buffer = [0; 1];
            read_bytes(instructions, &mut buffer)?;
            offset |= (buffer[0] as usize) << (index * 8);
        }
        // 1 ビット分右シフトして、次のビットをチェックできるようにする
        instruction >>= 1;
    }

    // 続く 3 ビットが size のバイト数を示す。
    // 同様に、ビットが立っていれば 1 バイト読み込み、(index*8) だけ左シフトして size に格納する。
    let mut size = 0;
    for index in 0..3 {
        if instruction & 0b0000_0001 != 0 {
            let mut buffer = [0; 1];
            read_bytes(instructions, &mut buffer)?;
            size |= (buffer[0] as usize) << (index * 8);
        }
        instruction >>= 1;
    }

    // size が 0 の場合は 65536 (0x10000) と解釈する
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
        // 命令 1 バイトを読み込む (もしここでデータが尽きたら break)
        if read_bytes(&mut delta_data, &mut instruction).is_err() {
            break;
        }

        // Insert 命令: MSBが 0 の場合
        if instruction[0] & 0b1000_0000 == 0 {
            let add_size = instruction[0];

            // insert するバイト数だけ読み込んで、それをそのまま出力に追加
            let mut data = vec![0; add_size as usize];
            delta_data.read_exact(&mut data)?;
            reconstruct_content.extend(data);

        // Copy 命令: MSB が 1 の場合
        } else {
            // offset と size を読み取り、その範囲を base_content からコピーする
            let (offset, size) =
                read_copy_instruction_offset_and_size(instruction[0], &mut delta_data)?;
            // base_content の [offset..offset+size] をコピー
            let copy_data = base_content.get(offset..(offset + size)).unwrap();
            reconstruct_content.extend_from_slice(copy_data);
        }
    }

    Ok(reconstruct_content)
}

fn unpack<R: Read>(reader: R) -> Result<HashMap<String, (Vec<u8>, PackObjectType)>> {
    let mut pack = BufReader::new(reader);

    let (_, _, entries) = read_header(&mut pack)?;

    let mut stores = HashMap::<String, (Vec<u8>, PackObjectType)>::new();
    for _ in 0..entries {
        let mut content_size = 0_usize;
        let (is_continue, obj_type, first_size) = read_type_and_size(&mut pack)?;
        content_size += first_size as usize;

        if is_continue {
            let size = read_size(&mut pack)?;
            content_size += size << 4;
        }

        match obj_type {
            PackObjectType::RefDelta => {
                let base_hash = read_hash(&mut pack)?;

                let (delta_data, _, _) = read_compressed_data(&mut pack, content_size)?;
                let (base_content, obj_type) = stores
                    .get(&base_hash)
                    .context("failed to get base content")?;

                let reconstruct_content = reconstruct(&delta_data, base_content)?;
                let hash = hash(obj_type, &reconstruct_content);
                stores.insert(hash, (reconstruct_content, obj_type.clone()));
            }
            PackObjectType::OfsDelta => {}
            _ => {
                let (content, _, _) = read_compressed_data(&mut pack, content_size)?;
                let hash = hash(&obj_type, &content);
                stores.insert(hash, (content, obj_type));
            }
        }
    }

    Ok(stores)
}
