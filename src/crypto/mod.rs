// Filesafe - Secure file vault
// Copyright (C) 2023 James Andrus
// Email: jandrus@citadel.edu

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::fs::{self, File};
use std::io::{Error, Read, Write};
use std::path::{Path, PathBuf};
use std::str::from_utf8;
use std::sync::mpsc::{channel, Receiver, Sender};

use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::decode;
use cocoon::Cocoon;
use flate2::read::GzEncoder;
use flate2::write::GzDecoder;
use flate2::Compression;
use fs_extra::dir::{self, get_dir_content2, DirOptions};
use rand::Rng;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};
use secstr::{SecStr, SecVec};
use sha2::{Digest, Sha256};
use tar::Archive;
use threadpool::ThreadPool;
use zeroize::Zeroize;

use filesafe;

#[derive(Clone)]
pub struct Keys {
    pub sk: SecVec<u8>,
    pub pk_export: String,
}

const MIN_BYTES: usize = 3000000;

pub fn decrypt_msg(msg: &str, keys: Keys) -> Result<String> {
    let ciphertext = decode(msg)?;
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let server_sk = RsaPrivateKey::from_pkcs1_pem(from_utf8(keys.sk.unsecure()).unwrap())
        .with_context(|| "Failed to load SK")?;
    let mut dec_data = server_sk.decrypt(padding, &ciphertext)?;
    let msg = from_utf8(&dec_data)?.to_string();
    dec_data.zeroize();
    Ok(msg)
}

pub fn gen_keys() -> Result<Keys> {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let mut sk = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate RSA Private Key");
    let pk = RsaPublicKey::from(&sk);
    let pk_export = EncodeRsaPublicKey::to_pkcs1_pem(&pk, rsa::pkcs1::LineEnding::CRLF)
        .with_context(|| "Failed to generate PEM")?;
    // SK exported so it can be encrypted in mem -> see type of Keys.sk
    let sk_export = EncodeRsaPrivateKey::to_pkcs1_pem(&sk, rsa::pkcs1::LineEnding::CRLF)
        .with_context(|| "Failed to generate PEM")?
        .to_string();
    filesafe::log_event("RSA Keys generated successfully", filesafe::LogLevel::Info);
    let secure_sk = SecStr::from(sk_export);
    sk.zeroize();
    Ok(Keys {
        sk: secure_sk,
        pk_export,
    })
}

pub fn lock(password: &str, protected_dir: &str) -> Result<()> {
    let is_valid = verify_password(password)?;
    ensure!(is_valid, "Lock attempt with INVALID password");
    compress(protected_dir)?;
    filesafe::shred_dir(protected_dir)?;
    fs::create_dir(protected_dir)?;
    split_file()?;
    filesafe::log_event("Begin shred of TAR file", filesafe::LogLevel::Performance);
    match nozomi::erase_file(filesafe::FILESAFE_TAR, nozomi::EraserEntity::PseudoRandom) {
        Ok(_) => (),
        Err(e) => {
            bail!("{}", e);
        }
    };
    filesafe::log_event("End shred of TAR file", filesafe::LogLevel::Performance);
    encrypt_files(password)?;
    filesafe::shred_dir(filesafe::FILESAFE_COMPRESSED_DIR)?;
    fs::create_dir(filesafe::FILESAFE_COMPRESSED_DIR)?;
    filesafe::log_event("Filesafe LOCKED", filesafe::LogLevel::Info);
    Ok(())
}

pub fn unlock(password: &str) -> Result<()> {
    let is_valid = verify_password(password)?;
    ensure!(is_valid, "Unlock attempt with INVALID password");
    filesafe::log_event("Filesafe UNLOCK initiated", filesafe::LogLevel::Performance);
    decrypt_files(password)?;
    assemble_files()?;
    decompress()?;
    filesafe::shred_dir(filesafe::FILESAFE_COMPRESSED_DIR)?;
    fs::create_dir(filesafe::FILESAFE_COMPRESSED_DIR)?;
    fs::remove_dir_all(filesafe::FILESAFE_ENCRYPTED_DIR)?;
    fs::create_dir(filesafe::FILESAFE_ENCRYPTED_DIR)?;
    filesafe::log_event("Filesafe UNLOCKED", filesafe::LogLevel::Info);
    Ok(())
}

pub fn verify_password(password: &str) -> Result<bool> {
    let pw_hash = read_file(filesafe::FILESAFE_SHADOW)?;
    let split = pw_hash.split(":");
    let v = split.collect::<Vec<&str>>();
    ensure!(v.len() == 2, "Previous password saved incorrectly");
    let salt = v[0];
    let orig_hash = v[1];
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.update(&salt);
    let hash = hex::encode(hasher.finalize());
    Ok(hash == orig_hash)
}

pub fn save_password(password: &str) -> Result<()> {
    let mut hasher = Sha256::new();
    let salt = hex::encode(rand::thread_rng().gen::<[u8; 16]>());
    hasher.update(password);
    hasher.update(&salt);
    let hash = hex::encode(hasher.finalize());
    if Path::new(filesafe::FILESAFE_SHADOW).exists() {
        fs::remove_file(filesafe::FILESAFE_SHADOW)?;
    }
    let mut f = File::create(filesafe::FILESAFE_SHADOW)?;
    let pw_hash = format!("{}:{}", &salt, hash);
    f.write_all(pw_hash.as_bytes())?;
    filesafe::log_event("Password saved", filesafe::LogLevel::Debug);
    Ok(())
}

fn compress(dir_to_compress: &str) -> Result<()> {
    filesafe::log_event("Compression initiated", filesafe::LogLevel::Performance);
    let tar_gz = File::create(filesafe::FILESAFE_TAR)?;
    // Zlib flate2
    // let flate_encoder = ZlibEncoder::new(tar_gz, Compression::fast());
    // let mut tar = tar::Builder::new(flate_encoder);
    // Gz flate2
    let flate_encoder = GzEncoder::new(tar_gz, Compression::fast());
    let mut tar = tar::Builder::new(flate_encoder);
    // zstd
    // let zencoder = match Encoder::new(tar_gz, COMPRESSION_LEVEL) {
    //     Ok(enc) => enc,
    //     Err(e) => return Err(e),
    // };
    // let mut tar = tar::Builder::new(zencoder);
    // just TAR
    // let mut tar = tar::Builder::new(tar_gz);
    tar.append_dir_all(filesafe::FILESAFE_DECOMPRESS_TEMP, dir_to_compress)?;
    tar.finish()?;
    filesafe::log_event("Compression complete", filesafe::LogLevel::Performance);
    Ok(())
}

fn decompress() -> Result<()> {
    filesafe::log_event("Decompression initiated", filesafe::LogLevel::Performance);
    if Path::new(filesafe::FILESAFE_DECOMPRESS_TEMP).exists() {
        fs::remove_dir_all(filesafe::FILESAFE_DECOMPRESS_TEMP)?;
    }
    fs::create_dir_all(filesafe::FILESAFE_DECOMPRESS_TEMP)?;
    let compressed_file = File::open(filesafe::FILESAFE_TAR)?;
    // flate2 Zlib
    // let decoder = ZlibDecoder::new(compressed_file);
    // let mut archive = Archive::new(decoder);
    // flate2 Gz
    let decoder = GzDecoder::new(compressed_file);
    let mut archive = Archive::new(decoder);
    // Zstd
    // let decoder = match Decoder::new(compressed_file) {
    //     Ok(dec) => dec,
    //     Err(e) => return Err(e),
    // };
    // just TAR
    // let mut archive = Archive::new(compressed_file);
    let entries = archive.entries()?;
    let filtered_entries = entries.filter_map(|e| e.ok());
    let mapped_entries = filtered_entries.map(|mut entry| -> Result<PathBuf, Error> {
        let path = entry
            .path()
            .expect("Error with entry path")
            .to_path_buf()
            .to_owned();
        match entry.unpack(&path) {
            Ok(_) => (),
            Err(e) => return Err(e),
        };
        Ok(path)
    });
    let me = mapped_entries.filter_map(|e| e.ok());
    let mut count = 0;
    me.for_each(|_x| count += 1);
    filesafe::log_event("Decompression complete", filesafe::LogLevel::Performance);
    Ok(())
}

fn encrypt_file(password: &str, outfile: &str, infile: &str) -> Result<()> {
    if Path::new(outfile).exists() {
        fs::remove_file(outfile)?;
    }
    let mut output_file = File::create(outfile)?;
    let contents = get_file_bytes(infile)?;
    let cocoon = Cocoon::new(password.as_bytes());
    match cocoon.dump(contents, &mut output_file) {
        Ok(_) => Ok(()),
        Err(e) => {
            return Err(anyhow!("Cacoon Error: {:?}", e));
        }
    }
}

fn encrypt_files(password: &str) -> Result<()> {
    filesafe::log_event("Encryption initiated", filesafe::LogLevel::Performance);
    let pool = ThreadPool::new(num_cpus::get());
    let (tx, rx): (Sender<Result<()>>, Receiver<Result<()>>) = channel();
    let options = DirOptions::new();
    let compressed_files = get_dir_content2(filesafe::FILESAFE_COMPRESSED_DIR, &options)?.files;
    for file in compressed_files {
        if !file.contains(filesafe::FILESAFE_TAR) {
            continue;
        }
        let part = file
            .split(".")
            .last()
            .with_context(|| "Encryption part file misconfigured")?;
        let outfile = format!("{}.{}", filesafe::FILESAFE_ENC, part);
        let tx = tx.clone();
        let pw = password.to_string().clone();
        pool.execute(move || {
            let res = encrypt_file(&pw, &outfile, &file);
            tx.send(res)
                .expect("[TX encrypt_files] Could not send data");
        });
    }
    drop(tx);
    for x in rx.iter() {
        match x {
            Ok(_) => (),
            Err(e) => return Err(e),
        };
    }
    filesafe::log_event("Encryption complete", filesafe::LogLevel::Performance);
    Ok(())
}

fn decrypt_files(password: &str) -> Result<()> {
    filesafe::log_event("Decryption initiated", filesafe::LogLevel::Performance);
    let pool = ThreadPool::new(num_cpus::get());
    let (tx, rx): (Sender<Result<()>>, Receiver<Result<()>>) = channel();
    let options = DirOptions::new();
    let encrypted_files = get_dir_content2(filesafe::FILESAFE_ENCRYPTED_DIR, &options)?.files;
    for file in encrypted_files {
        if !file.contains(filesafe::FILESAFE_ENC) {
            continue;
        }
        let part = file
            .split(".")
            .last()
            .with_context(|| "Encrypted part file misconfigured")?;
        let outfile = format!("{}.{}", filesafe::FILESAFE_TAR, part);
        let tx = tx.clone();
        let pw = password.to_string().clone();
        pool.execute(move || {
            let res = decrypt_file(&pw, &file, &outfile);
            tx.send(res)
                .expect("[TX decrypt_files] Could not send data");
        });
    }
    drop(tx);
    for x in rx.iter() {
        match x {
            Ok(_) => (),
            Err(e) => return Err(e),
        };
    }
    filesafe::log_event("Decryption complete", filesafe::LogLevel::Performance);
    Ok(())
}

fn decrypt_file(password: &str, infile: &str, outfile: &str) -> Result<()> {
    let cocoon = Cocoon::new(password.as_bytes());
    let mut input_file = File::open(infile)?;
    let data = match cocoon.parse(&mut input_file) {
        Ok(d) => d,
        Err(e) => {
            bail!("Cacoon Error: {:?}", e);
        }
    };
    let mut out_file = File::create(outfile)?;
    out_file.write_all(&data)?;
    Ok(())
}

fn split_file() -> Result<()> {
    let threads_avail = num_cpus::get() as usize;
    let dir_size = dir::get_size(filesafe::FILESAFE_COMPRESSED_DIR)?;
    let mut compresssed_file = File::open(filesafe::FILESAFE_TAR)?;
    let mut file_bytes = Vec::new();
    compresssed_file.read_to_end(&mut file_bytes)?;
    let mut bytes_per_file = (dir_size as f64 / threads_avail as f64).ceil() as usize;
    let mut num_files = threads_avail;
    if bytes_per_file < MIN_BYTES {
        num_files = (dir_size as f64 / MIN_BYTES as f64).ceil() as usize;
        bytes_per_file = MIN_BYTES;
        if MIN_BYTES > dir_size as usize {
            bytes_per_file = dir_size as usize;
        }
    }
    let mut index = 0 as usize;
    for i in 1..num_files {
        let filename = format!("{}.{:03}", filesafe::FILESAFE_TAR, i);
        let mut buf = File::create(&filename)?;
        buf.write_all(&file_bytes[index..index + bytes_per_file])?;
        index += bytes_per_file;
    }
    let filename = format!("{}.{:03}", filesafe::FILESAFE_TAR, num_files);
    let mut buf = File::create(&filename)?;
    buf.write_all(&file_bytes[index..])?;
    // fs::remove_file(filesafe::FILESAFE_TAR)?;
    Ok(())
}

fn assemble_files() -> Result<()> {
    let options = DirOptions::new();
    let mut compressed_files = get_dir_content2(filesafe::FILESAFE_COMPRESSED_DIR, &options)?.files;
    let mut file_bytes = Vec::new();
    compressed_files.sort();
    for file in compressed_files {
        if !file.contains(filesafe::FILESAFE_TAR) {
            continue;
        }
        let mut compresssed_file = File::open(&file)?;
        compresssed_file.read_to_end(&mut file_bytes)?;
    }
    let mut f = File::create(filesafe::FILESAFE_TAR)?;
    f.write_all(&file_bytes)?;
    Ok(())
}

fn get_file_bytes(file_name: &str) -> Result<Vec<u8>, Error> {
    match fs::read(file_name) {
        Ok(contents) => Ok(contents),
        Err(e) => Err(e),
    }
}

fn read_file(path: &str) -> Result<String> {
    let mut s = String::new();
    let mut f = File::open(path)?;
    match f.read_to_string(&mut s) {
        Ok(_) => Ok(s),
        Err(e) => Err(anyhow!("{}", e)),
    }
}
