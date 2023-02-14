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

use anyhow::{anyhow, bail, ensure, Result};
use chrono::{Local, NaiveDateTime};
use fs_extra::dir::{self, get_dir_content2, CopyOptions, DirOptions};
use sha2::{Digest, Sha256};
use std::fs::{self, create_dir_all, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use threadpool::ThreadPool;

#[derive(Clone, Debug)]
pub struct ServerParams {
    pub port: String,
    pub ip: String,
    pub timeout: usize,
    pub protected_dir: String,
    pub auto_bu_params: AutoBackup,
    pub sec_backup_dir: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AutoBackup {
    pub frequency: AutoBackupFrequency,
    pub time: usize,
    pub day: AutoBackupDay,
}

#[derive(Clone, Debug)]
pub enum AutoBackupFrequency {
    None,
    Daily,
    Weekly,
    Invalid,
}

#[derive(Clone, Debug)]
pub enum AutoBackupDay {
    Mon,
    Tue,
    Wed,
    Thr,
    Fri,
    Sat,
    Sun,
    Invalid,
}

pub enum LogLevel {
    Info,
    Error,
    Debug,
    Performance,
}

pub const FILESAFE_COMPRESSED_DIR: &str = ".compressed";
pub const FILESAFE_ENCRYPTED_DIR: &str = "encrypted";
pub const FILESAFE_BACKUP_DIR: &str = "backup";
pub const FILESAFE_DECOMPRESS_TEMP: &str = ".tmp";
pub const FILESAFE_TAR: &str = ".compressed/protected.tar.gz";
pub const FILESAFE_ENC: &str = "encrypted/files.safe";
pub const FILESAFE_SHADOW: &str = ".filesafe.shadow";
pub const FILESAFE_LOG: &str = "filesafe-server.log";
pub const MAX_PASS_ATTEMPT: usize = 3;

pub fn is_unlocked(protected_dir: &str) -> Result<bool> {
    let is_locked = is_locked()?;
    if is_locked {
        return Ok(false);
    }
    let mut count = 0;
    for _entry in fs::read_dir(protected_dir)? {
        count += 1;
    }
    Ok(count > 0 && Path::new(FILESAFE_SHADOW).exists())
}

pub fn is_locked() -> Result<bool> {
    let mut count = 0;
    for _entry in fs::read_dir(FILESAFE_ENCRYPTED_DIR)? {
        count += 1;
    }
    Ok(count > 0 && Path::new(FILESAFE_SHADOW).exists())
}

pub fn log_event(e: &str, level: LogLevel) {
    let now_ts = Local::now().timestamp() - 18000;
    let now = NaiveDateTime::from_timestamp_opt(now_ts, 0).unwrap();
    let event_msg: String;
    match level {
        LogLevel::Info => {
            let print_msg = format!("[{now}] {e}\n");
            print!("{}", print_msg);
            event_msg = format!("[{now}] <Info> {e}\n");
        }
        LogLevel::Error => {
            let print_msg = format!("[{now}] {e}\n");
            print!("{}", print_msg);
            event_msg = format!("[{now}] <Error> {e}\n");
        }
        LogLevel::Debug => event_msg = format!("[{now}] <Debug> {e}\n"),
        LogLevel::Performance => event_msg = format!("[{now}] <Performance> {e}\n"),
    };
    if Path::new(FILESAFE_LOG).exists() {
        let mut f = OpenOptions::new()
            .append(true)
            .open(FILESAFE_LOG)
            .expect("Unable to open log file for appending.");
        f.write_all(event_msg.as_bytes())
            .expect("Unable to append to log.");
    } else {
        let mut f = File::create(FILESAFE_LOG).unwrap();
        f.write_all(event_msg.as_bytes())
            .expect("Unable to write initial event to log.");
    }
}

pub fn create_backup(secondary_backup: &Option<String>) -> Result<String> {
    let is_locked = is_locked()?;
    if !is_locked {
        bail!("Backup failed. Files not found for backup.");
    }
    let now_ts = Local::now().timestamp() - 18000;
    let backup_dir = format!("{}/filesafe-{}", FILESAFE_BACKUP_DIR, now_ts);
    create_dir_all(&backup_dir)?;
    let backup_tar_name = format!("{}/filesafe.backup", backup_dir);
    let backup_tar = File::create(&backup_tar_name)?;
    let hash_file_name = format!("{}/filesafe.hash", backup_dir);
    let mut hash_file = File::create(&hash_file_name)?;
    let mut tar_file = tar::Builder::new(backup_tar);
    for entry in fs::read_dir(FILESAFE_ENCRYPTED_DIR)? {
        let file = entry?.path().into_os_string().into_string().unwrap();
        if file.contains(FILESAFE_ENC) {
            let mut f = File::open(&file)?;
            tar_file.append_file(&file, &mut f)?;
        }
    }
    let hash = get_file_hash(&backup_tar_name)?;
    let mut f = File::open(FILESAFE_SHADOW)?;
    tar_file.append_file(FILESAFE_SHADOW, &mut f)?;
    hash_file.write_all(hash.as_bytes())?;
    log_event("Backup saved", LogLevel::Debug);
    match secondary_backup {
        Some(dir) => {
            let mut options = CopyOptions::new();
            options.skip_exist = true;
            options.copy_inside = true;
            let mut from_paths = Vec::new();
            from_paths.push(backup_dir.clone());
            fs_extra::copy_items(&from_paths, dir, &options)?;
            log_event("Secondary backup saved", LogLevel::Debug);
        }
        None => (),
    };
    clean_backups(secondary_backup)?;
    Ok(backup_dir)
}

pub fn restore_files(protected_dir: &str) -> Result<()> {
    let mut options = CopyOptions::new();
    options.skip_exist = true;
    options.copy_inside = true;
    let mut dir_options = DirOptions::new();
    dir_options.depth = 1;
    let dir_content = get_dir_content2(FILESAFE_DECOMPRESS_TEMP, &dir_options)?;
    let mut from_paths = Vec::new();
    for dir in dir_content.directories {
        if dir == FILESAFE_DECOMPRESS_TEMP {
            continue;
        }
        from_paths.push(dir);
    }
    for f in dir_content.files {
        from_paths.push(f);
    }
    fs_extra::move_items(&from_paths, protected_dir, &options)?;
    // shred_dir(FILESAFE_DECOMPRESS_TEMP)?;
    fs::remove_dir_all(FILESAFE_DECOMPRESS_TEMP)?;
    log_event("Files restored", LogLevel::Info);
    Ok(())
}

pub fn shred_dir(directory: &str) -> Result<()> {
    let event = format!("Begin shred of {} directory", directory);
    log_event(&event, LogLevel::Performance);
    let pool = ThreadPool::new(num_cpus::get());
    let (tx, rx): (Sender<Result<()>>, Receiver<Result<()>>) = channel();
    let all_files = get_all_files(directory)?;
    for file in all_files {
        if !Path::new(&file).exists() {
            continue;
        }
        // println!("{}", file);
        let tx = tx.clone();
        pool.execute(move || {
            let res = match nozomi::erase_file(&file, nozomi::EraserEntity::PseudoRandom) {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow!("Error erasing file {} [{}]", file, e)),
            };
            tx.send(res).expect("Unable to send to tx {file}");
        });
    }
    drop(tx);
    for x in rx.iter() {
        match x {
            Ok(_) => (),
            Err(e) => return Err(e),
        };
    }
    let event = format!("Complete shred of FILES in {} directory", directory);
    log_event(&event, LogLevel::Debug);
    match nozomi::erase_folder(directory, nozomi::EraserEntity::PseudoRandom, true) {
        Ok(_) => (),
        Err(e) => {
            bail!("{}", e);
        }
    };
    let event = format!("End shred of {} directory", directory);
    log_event(&event, LogLevel::Performance);
    Ok(())
}

pub fn remove_child_paths(directory: &str) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.metadata()?.is_dir() {
            fs::remove_dir_all(entry.path().into_os_string().into_string().unwrap())?;
        } else {
            fs::remove_file(entry.path().into_os_string().into_string().unwrap())?;
        }
    }
    Ok(())
}

fn get_all_files(directory: &str) -> Result<Vec<String>> {
    let mut files: Vec<String> = Vec::new();
    let dir = fs::read_dir(directory)?;
    for entry in dir {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::metadata(&path)?;
        if metadata.is_dir() {
            let dir = match path.to_str() {
                Some(s) => s,
                None => continue,
            };
            files.append(&mut get_all_files(dir)?);
        } else {
            files.append(&mut vec![path.into_os_string().into_string().unwrap()]);
        }
    }
    Ok(files)
}

fn clean_backups(secondary_backup: &Option<String>) -> Result<()> {
    let mut hashes: Vec<String> = Vec::new();
    let directories = fs::read_dir(FILESAFE_BACKUP_DIR)?;
    for dir in directories {
        let dir_entry = dir?;
        let metadata = dir_entry.metadata()?;
        if metadata.is_dir() {
            let dir_str = dir_entry.path().display().to_string();
            let dir_name = dir_str
                .split("/")
                .collect::<Vec<&str>>()
                .last()
                .copied()
                .unwrap();
            if dir_name.starts_with("filesafe") {
                let hash = read_file_string(&format!("{}/filesafe.hash", dir_str))?;
                if hashes.contains(&hash) {
                    log_event(
                        &format!("Duplicate backup removed: {}", dir_str),
                        LogLevel::Info,
                    );
                    dir::remove(dir_str)?;
                } else {
                    hashes.push(hash.clone());
                }
            }
        }
    }
    let mut hashes: Vec<String> = Vec::new();
    match secondary_backup {
        Some(dir) => {
            let directories = fs::read_dir(dir)?;
            for dir in directories {
                let dir_entry = dir?;
                let metadata = dir_entry.metadata()?;
                if metadata.is_dir() {
                    let dir_str = dir_entry.path().display().to_string();
                    let dir_name = dir_str
                        .split("/")
                        .collect::<Vec<&str>>()
                        .last()
                        .copied()
                        .unwrap();
                    if dir_name.starts_with("filesafe") {
                        let hash = read_file_string(&format!("{}/filesafe.hash", dir_str))?;
                        if hashes.contains(&hash) {
                            log_event(
                                &format!("Duplicate backup removed: {}", dir_str),
                                LogLevel::Info,
                            );
                            dir::remove(dir_str)?;
                        } else {
                            hashes.push(hash.clone());
                        }
                    }
                }
            }
        }
        None => (),
    };
    Ok(())
}

fn get_file_hash(f: &str) -> Result<String> {
    let content = read_file(f)?;
    let mut hasher = Sha256::new();
    hasher.update(content);
    Ok(hex::encode(hasher.finalize()))
}

fn read_file(filename: &str) -> Result<Vec<u8>> {
    let path = Path::new(filename);
    ensure!(path.exists(), "File {filename} not found");
    let mut content = Vec::new();
    let mut f = File::open(filename)?;
    f.read_to_end(&mut content)?;
    Ok(content)
}

fn read_file_string(path: &str) -> Result<String> {
    let mut s = String::new();
    let mut f = File::open(path)?;
    match f.read_to_string(&mut s) {
        Ok(_) => Ok(s),
        Err(e) => bail!("{}", e),
    }
}
