// Filesafe - Secure file vault
// Copyright (C) 2023 James Andrus
// Email: jandrus@citadel.edu

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use anyhow::{bail, ensure, Context, Result};
use clap::ArgMatches;
use fs_extra::dir;
use ini::Ini;
use pnet_datalink::interfaces;
use tar::Archive;
use zeroize::Zeroize;

use std::env::{current_dir, set_current_dir, var};
use std::fs::{self, create_dir_all, File};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::Path;

use crate::crypto;
use filesafe;

const FILESAFE_CONF: &str = "filesafe.ini";

pub fn setup_server_params(matches: ArgMatches) -> Result<filesafe::ServerParams> {
    let current_dir = current_dir()
        .expect("Error getting current working directory")
        .to_str()
        .expect("Error getting current working directory")
        .to_string();
    let safe_dir = get_filesafe_dir()?;
    set_current_dir(&safe_dir)?;
    match matches.value_source("pass") {
        Some(_) => {
            let pass = matches
                .get_one::<String>("pass")
                .expect("Password not given in args")
                .to_string();
            let is_valid = crypto::verify_password(&pass)?;
            ensure!(is_valid, "Invalid password given via args");
        }
        None => (),
    };
    check_file_structure()?;
    get_server_params(matches.clone(), current_dir, safe_dir)
}

pub fn setup_interractive(protected_dir: &str, secondary_backup: &Option<String>) -> Result<()> {
    lock_or_unlock_dialog(protected_dir)?;
    let is_locked = filesafe::is_locked()?;
    let is_unlocked = filesafe::is_unlocked(protected_dir)?;
    if is_locked || is_unlocked {
        filesafe::log_event("Filesafe detected", filesafe::LogLevel::Info);
    } else {
        filesafe::log_event("No prior filesafe detected", filesafe::LogLevel::Info);
    }
    let did_restore = backup_prompt(0, protected_dir, secondary_backup)?;
    if did_restore {
        // fs::remove_dir(filesafe::FILESAFE_ENCRYPTED_DIR)?;
        // fs::create_dir_all(filesafe::FILESAFE_ENCRYPTED_DIR)?;
        // fs::remove_file(filesafe::FILESAFE_SHADOW)?;
        lock_or_unlock_dialog(protected_dir)?;
    }
    let is_locked = filesafe::is_locked()?;
    let is_unlocked = filesafe::is_unlocked(protected_dir)?;
    if is_locked || is_unlocked {
        filesafe_setup(protected_dir, secondary_backup)?;
    } else {
        initial_filesafe_setup()?;
    }
    Ok(())
}

pub fn setup_non_interractive(protected_dir: &str, matches: ArgMatches) -> Result<()> {
    let is_locked = filesafe::is_locked()?;
    let is_unlocked = filesafe::is_unlocked(protected_dir)?;
    if is_locked {
        filesafe::log_event("Filesafe is Locked", filesafe::LogLevel::Info);
    } else if is_unlocked {
        filesafe::log_event("Filesafe is Unlocked", filesafe::LogLevel::Info);
    } else {
        filesafe::log_event("No prior filesafe detected", filesafe::LogLevel::Info);
        return initial_filesafe_setup();
    }
    if matches.get_flag("lock") {
        if is_unlocked {
            match matches.value_source("pass") {
                Some(_) => {
                    let password = matches.get_one::<String>("pass").unwrap().to_string();
                    lock_with_pass(protected_dir, password)?;
                }
                None => {
                    lock_if_unlocked(0, protected_dir)?;
                }
            };
        }
    }
    if matches.get_flag("unlock") {
        if is_locked {
            match matches.value_source("pass") {
                Some(_) => {
                    let password = matches.get_one::<String>("pass").unwrap().to_string();
                    unlock_with_pass(password)?;
                    filesafe::restore_files(protected_dir)?;
                }
                None => {
                    unlock_if_locked(0)?;
                    filesafe::restore_files(protected_dir)?;
                }
            };
        }
    }
    Ok(())
}

fn unlock_with_pass(mut password: String) -> Result<()> {
    let is_valid_pass = crypto::verify_password(&password)?;
    ensure!(is_valid_pass, "Invalid password");
    filesafe::log_event("Valid password received", filesafe::LogLevel::Info);
    filesafe::log_event("Unlocking filesafe", filesafe::LogLevel::Info);
    match crypto::unlock(&password) {
        Ok(_) => {
            password.zeroize();
            return Ok(());
        }
        Err(e) => {
            password.zeroize();
            return Err(e);
        }
    }
}

fn lock_with_pass(protected_dir: &str, mut password: String) -> Result<()> {
    let is_valid_pass = crypto::verify_password(&password)?;
    ensure!(is_valid_pass, "Invalid password");
    filesafe::log_event("Valid password received", filesafe::LogLevel::Info);
    filesafe::log_event("Locking filesafe", filesafe::LogLevel::Info);
    match crypto::lock(&password, protected_dir) {
        Ok(_) => {
            password.zeroize();
            return Ok(());
        }
        Err(e) => {
            password.zeroize();
            return Err(e);
        }
    }
}

fn initial_filesafe_setup() -> Result<()> {
    filesafe::log_event("Begin initial setup", filesafe::LogLevel::Info);
    let mut password = get_initial_password(0)?;
    crypto::save_password(&password)?;
    password.zeroize();
    filesafe::log_event("Initial setup complete", filesafe::LogLevel::Info);
    Ok(())
}

fn get_initial_password(mut num_tries: usize) -> Result<String> {
    if num_tries != 0 {
        println!(
            "Passwords do not match {} attempts remaining",
            filesafe::MAX_PASS_ATTEMPT - num_tries
        );
    }
    let pw_0 = rpassword::prompt_password("Enter password: ")?;
    let mut pw_1 = rpassword::prompt_password("Re-enter password: ")?;
    if pw_0 != pw_1 {
        num_tries += 1;
        ensure!(
            num_tries < filesafe::MAX_PASS_ATTEMPT,
            "Password attempts exceeded limit"
        );
        return get_initial_password(num_tries);
    }
    pw_1.zeroize();
    Ok(pw_0)
}

fn backup_prompt(
    mut num_tries: usize,
    protected_dir: &str,
    secondary_backup: &Option<String>,
) -> Result<bool> {
    ensure!(
        num_tries < filesafe::MAX_PASS_ATTEMPT,
        "Max attempts exceeded [backup_prompt]"
    );
    let prev_backups = get_prev_backups(secondary_backup)?;
    if prev_backups.len() == 0 {
        return Ok(false);
    }
    let mut ans = String::new();
    print!("Restore backup? [y/n]: ");
    let _ = io::stdout().flush();
    let _byt = io::stdin().read_line(&mut ans)?;
    let processed_ans = &ans.to_lowercase().trim().to_string();
    if processed_ans == "y" {
        let is_unlocked = filesafe::is_unlocked(protected_dir)?;
        let restore_dir = get_restore_dir(0, prev_backups)?.to_string();
        if is_unlocked {
            println!("Filesafe is currently unlocked. Restoring backup with unlocked filesafe may corrupt unlocked files.\nEnter password to lock current filesafe and restore backup.");
            lock_if_unlocked(0, protected_dir)?;
        }
        let is_locked = filesafe::is_locked()?;
        ensure!(
            is_locked,
            "Attempted to create backup of non-locked filesafe."
        );
        filesafe::log_event(
            "Creating backup of current filesafe",
            filesafe::LogLevel::Info,
        );
        let backup = filesafe::create_backup(secondary_backup)?;
        let event = format!("Backup {} created", backup);
        filesafe::log_event(&event, filesafe::LogLevel::Info);
        fs::remove_dir(filesafe::FILESAFE_ENCRYPTED_DIR)?;
        fs::create_dir_all(filesafe::FILESAFE_ENCRYPTED_DIR)?;
        fs::remove_file(filesafe::FILESAFE_SHADOW)?;
        restore_backup(&restore_dir)?;
        return Ok(true);
    }
    if processed_ans == "n" {
        return Ok(false);
    }
    println!("Invalid input");
    num_tries += 1;
    backup_prompt(num_tries, protected_dir, secondary_backup)
}

fn restore_backup(dir: &str) -> Result<()> {
    let backup_tar_file = File::open(format!("{}/filesafe.backup", dir))?;
    let mut archive = Archive::new(backup_tar_file);
    archive.unpack(".")?;
    let event = format!("Backup {} restored", dir);
    filesafe::log_event(&event, filesafe::LogLevel::Info);
    Ok(())
}

fn get_restore_dir(mut num_tries: usize, prev_backups: Vec<String>) -> Result<String> {
    ensure!(
        num_tries < filesafe::MAX_PASS_ATTEMPT,
        "Max attempts exceeded [get_restore_dir]"
    );
    println!("Available backups:");
    let mut hashes: Vec<String> = Vec::new();
    for (i, backup) in prev_backups.iter().enumerate() {
        let dir_size = dir::get_size(backup)?;
        let size_str = get_readable_size(dir_size);
        let hash = read_file(&format!("{}/filesafe.hash", backup))?;
        if hashes.contains(&hash) {
            continue;
        }
        hashes.push(hash.clone());
        let backup_name = backup
            .split("/")
            .collect::<Vec<&str>>()
            .last()
            .copied()
            .unwrap();
        println!("{} ->\t{} ({}) [{}]", i, backup_name, hash, size_str);
    }
    let mut ans = String::new();
    print!("Choose backup? [num]: ");
    let _ = io::stdout().flush();
    let _byt = io::stdin().read_line(&mut ans)?;
    let processed_ans = &ans.trim().to_string();
    let index: i32;
    match &processed_ans.parse::<i32>() {
        Ok(n) => {
            if n >= &(0 as i32) && n < &(prev_backups.len() as i32) {
                index = *n;
            } else {
                index = -1;
            }
        }
        Err(_) => index = -1,
    };
    if index != -1 {
        match prev_backups.get(index.abs() as usize) {
            Some(d) => return Ok(d.to_string()),
            None => bail!("Invalid index"),
        };
    }
    println!("Invalid input");
    num_tries += 1;
    get_restore_dir(num_tries, prev_backups)
}

fn get_prev_backups(secondary_backup: &Option<String>) -> Result<Vec<String>> {
    let mut dirs: Vec<String> = Vec::new();
    let directories = fs::read_dir(filesafe::FILESAFE_BACKUP_DIR)?;
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
                dirs.push(dir_str);
            }
        }
    }
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
                        dirs.push(dir_str);
                    }
                }
            }
        }
        None => (),
    };
    Ok(dirs)
}

fn lock_or_unlock_dialog(protected_dir: &str) -> Result<()> {
    let is_unlocked = filesafe::is_unlocked(protected_dir)?;
    let is_locked = filesafe::is_locked()?;
    if is_unlocked {
        prompt_lock_if_unlocked(protected_dir)?;
        return Ok(());
    }
    if is_locked {
        prompt_unlock_if_locked(protected_dir)?;
    }
    Ok(())
}

fn prompt_lock_if_unlocked(protected_dir: &str) -> Result<()> {
    let mut ans = String::new();
    print!("Filesafe is unlocked. Would you like to lock it now? [Y/n]: ");
    let _ = io::stdout().flush();
    let _byt = io::stdin().read_line(&mut ans)?;
    let processed_ans = &ans.to_lowercase().trim().to_string();
    if processed_ans == "y" {
        lock_if_unlocked(0, protected_dir)?;
    }
    Ok(())
}

fn prompt_unlock_if_locked(protected_dir: &str) -> Result<()> {
    let mut ans = String::new();
    print!("Filesafe is locked. Would you like to unlock it now? [y/N]: ");
    let _ = io::stdout().flush();
    let _byt = io::stdin().read_line(&mut ans)?;
    let processed_ans = &ans.to_lowercase().trim().to_string();
    if processed_ans == "y" {
        unlock_if_locked(0)?;
        filesafe::restore_files(protected_dir)?;
    }
    Ok(())
}

fn unlock_if_locked(mut num_tries: usize) -> Result<()> {
    ensure!(
        num_tries < filesafe::MAX_PASS_ATTEMPT,
        "Max attempts exceeded [unlock]"
    );
    let mut pw = rpassword::prompt_password("Enter password: ")?;
    let is_valid_pass = crypto::verify_password(&pw)?;
    if is_valid_pass {
        filesafe::log_event("Valid password received", filesafe::LogLevel::Info);
        filesafe::log_event("Unlocking filesafe", filesafe::LogLevel::Info);
        match crypto::unlock(&pw) {
            Ok(_) => {
                pw.zeroize();
                return Ok(());
            }
            Err(e) => {
                pw.zeroize();
                return Err(e);
            }
        };
    }
    filesafe::log_event("Invalid password recieved", filesafe::LogLevel::Info);
    num_tries += 1;
    unlock_if_locked(num_tries)
}

fn lock_if_unlocked(mut num_tries: usize, protected_dir: &str) -> Result<()> {
    ensure!(
        num_tries < filesafe::MAX_PASS_ATTEMPT,
        "Max attempts exceeded [lock]"
    );
    let mut pw = rpassword::prompt_password("Enter password: ")?;
    let is_valid_pass = crypto::verify_password(&pw)?;
    if is_valid_pass {
        filesafe::log_event("Valid password received", filesafe::LogLevel::Info);
        filesafe::log_event("Locking filesafe", filesafe::LogLevel::Info);
        match crypto::lock(&pw, protected_dir) {
            Ok(_) => {
                pw.zeroize();
                return Ok(());
            }
            Err(e) => {
                pw.zeroize();
                return Err(e);
            }
        };
    }
    filesafe::log_event("Invalid password recieved", filesafe::LogLevel::Info);
    num_tries += 1;
    lock_if_unlocked(num_tries, protected_dir)
}

fn get_filesafe_dir() -> Result<String> {
    match var("HOME") {
        Ok(val) => {
            let filesafe_dir = format!("{}/.config/filesafe", val);
            if !Path::new(&filesafe_dir).exists() {
                create_dir_all(&filesafe_dir)
                    .with_context(|| "Failed to create Filesafe directory")?;
                println!("Filesafe directory created [{}]", filesafe_dir);
            }
            return Ok(filesafe_dir);
        }
        Err(e) => {
            bail!("Couldn't find users $HOME directory: {e}");
        }
    }
}

fn check_file_structure() -> Result<()> {
    if !Path::new(filesafe::FILESAFE_BACKUP_DIR).exists() {
        create_dir_all(filesafe::FILESAFE_BACKUP_DIR)?;
        format!(
            "Filesafe directory created [{}]",
            filesafe::FILESAFE_BACKUP_DIR
        );
    }
    if !Path::new(filesafe::FILESAFE_COMPRESSED_DIR).exists() {
        create_dir_all(filesafe::FILESAFE_COMPRESSED_DIR)?;
        println!(
            "Filesafe directory created [{}]",
            filesafe::FILESAFE_COMPRESSED_DIR
        );
    }
    if !Path::new(filesafe::FILESAFE_ENCRYPTED_DIR).exists() {
        create_dir_all(filesafe::FILESAFE_ENCRYPTED_DIR)?;
        println!(
            "Filesafe directory created [{}]",
            filesafe::FILESAFE_ENCRYPTED_DIR
        );
    }
    Ok(())
}

fn get_server_params_from_file(
    conf_file: &str,
    mut server_params: filesafe::ServerParams,
) -> Result<filesafe::ServerParams> {
    let conf = Ini::load_from_file(conf_file)?;
    let section = match conf.section(Some("SERVER")) {
        Some(s) => s,
        None => {
            bail!("Configuration file is misconfigured [section::SERVER]");
        }
    };
    match section.get("port") {
        Some(s) => server_params.port = s.to_string(),
        None => (),
    };
    match section.get("timeout") {
        Some(s) => {
            let timeout = s.to_string();
            server_params.timeout = timeout.parse::<usize>()?
        }
        None => (),
    };
    match section.get("protected_dir") {
        Some(s) => server_params.protected_dir = s.to_string(),
        None => (),
    };
    match section.get("auto_backup_freq") {
        Some(s) => match s.to_lowercase().as_str() {
            "n" => server_params.auto_bu_params.frequency = filesafe::AutoBackupFrequency::None,
            "d" => server_params.auto_bu_params.frequency = filesafe::AutoBackupFrequency::Daily,
            "w" => server_params.auto_bu_params.frequency = filesafe::AutoBackupFrequency::Weekly,
            &_ => server_params.auto_bu_params.frequency = filesafe::AutoBackupFrequency::Invalid,
        },
        None => (),
    };
    match section.get("auto_backup_time") {
        Some(s) => {
            let t = s.to_string();
            server_params.auto_bu_params.time = parse_time(t)?;
        }
        None => (),
    };
    match section.get("auto_backup_day") {
        Some(i) => {
            let day = i.to_string();
            match day.parse::<usize>() {
                Ok(t) => match t {
                    1 => server_params.auto_bu_params.day = filesafe::AutoBackupDay::Mon,
                    2 => server_params.auto_bu_params.day = filesafe::AutoBackupDay::Tue,
                    3 => server_params.auto_bu_params.day = filesafe::AutoBackupDay::Wed,
                    4 => server_params.auto_bu_params.day = filesafe::AutoBackupDay::Thr,
                    5 => server_params.auto_bu_params.day = filesafe::AutoBackupDay::Fri,
                    6 => server_params.auto_bu_params.day = filesafe::AutoBackupDay::Sat,
                    7 => server_params.auto_bu_params.day = filesafe::AutoBackupDay::Sun,
                    _ => server_params.auto_bu_params.day = filesafe::AutoBackupDay::Invalid,
                },
                Err(_) => server_params.auto_bu_params.day = filesafe::AutoBackupDay::Invalid,
            };
        }
        None => (),
    };
    match section.get("sec_backup_dir") {
        Some(s) => server_params.sec_backup_dir = Some(s.to_string()),
        None => (),
    };
    Ok(server_params)
}

fn get_server_params(
    matches: ArgMatches,
    current_dir: String,
    safe_dir: String,
) -> Result<filesafe::ServerParams> {
    let conf_file: &str;
    match matches.value_source("conf") {
        Some(_) => {
            conf_file = matches
                .get_one::<String>("conf")
                .expect("Args do not contain config file");
            set_current_dir(&current_dir)?;
            if !Path::new(conf_file).exists() {
                bail!("Provided configuration file does not exist");
            }
        }
        None => conf_file = FILESAFE_CONF,
    };
    let mut server_params = filesafe::ServerParams {
        port: "0".to_string(),
        ip: "0.0.0.0".to_string(),
        timeout: 0,
        protected_dir: "420".to_string(),
        auto_bu_params: filesafe::AutoBackup {
            frequency: filesafe::AutoBackupFrequency::Invalid,
            time: 2500,
            day: filesafe::AutoBackupDay::Invalid,
        },
        sec_backup_dir: None,
    };
    server_params = get_server_params_from_file(conf_file, server_params.clone())?;
    set_current_dir(&safe_dir)?;
    match matches.value_source("port") {
        Some(_) => {
            server_params.port = matches
                .get_one::<String>("port")
                .expect("Args do not contain port")
                .to_string();
        }
        None => (),
    }
    match server_params.port.parse::<usize>() {
        Ok(n) => {
            ensure!(n < 65535, "Port out of bounds");
        }
        Err(e) => {
            bail!("Port out of bounds: {}", e);
        }
    }
    ensure!(server_params.port != "0", "Invalid port");
    match matches.value_source("address") {
        Some(_) => {
            let address = matches
                .get_one::<String>("address")
                .expect("Args do not contain address")
                .to_string();
            address.parse::<IpAddr>()?;
            server_params.ip = address;
        }
        None => {
            server_params.ip = get_ip()?;
        }
    }
    ensure!(server_params.ip != "0.0.0.0", "Invalid ip address");
    match matches.value_source("directory") {
        Some(_) => {
            server_params.protected_dir = matches
                .get_one::<String>("directory")
                .expect("Args do not contain Protected Directory")
                .to_string();
        }
        None => (),
    }
    ensure!(
        Path::new(&server_params.protected_dir).exists(),
        "Protected directory DOES NOT EXIST (Directory must exist at runtime)"
    );
    match matches.value_source("timeout") {
        Some(_) => {
            let timeout = matches
                .get_one::<String>("timeout")
                .expect("Args do not contain timeout")
                .to_string();
            server_params.timeout = timeout.parse::<usize>()?;
        }
        None => (),
    };
    match matches.value_source("no timeout") {
        Some(_) => (),
        None => {
            ensure!(
                server_params.timeout >= 5,
                "Invalid timeout [timeout must be greater than 5]"
            );
        }
    };
    match matches.value_source("backup frequency") {
        Some(_) => {
            let freq = matches
                .get_one::<String>("backup frequency")
                .expect("Args do not contain backup frequency")
                .to_lowercase();
            match freq.as_str() {
                "n" => server_params.auto_bu_params.frequency = filesafe::AutoBackupFrequency::None,
                "d" => {
                    server_params.auto_bu_params.frequency = filesafe::AutoBackupFrequency::Daily
                }
                "w" => {
                    server_params.auto_bu_params.frequency = filesafe::AutoBackupFrequency::Weekly
                }
                _ => bail!("Invalid auto backup frequency"),
            }
        }
        None => (),
    };
    match matches.value_source("backup time") {
        Some(_) => {
            let time = matches
                .get_one::<String>("backup time")
                .expect("Args do not contain backup time")
                .to_string();
            server_params.auto_bu_params.time = parse_time(time)?;
        }
        None => (),
    };
    match matches.value_source("backup day") {
        Some(_) => {
            let day = matches
                .get_one::<String>("backup day")
                .expect("Args do not contain backup day")
                .to_string();
            match day.as_str() {
                "1" => server_params.auto_bu_params.day = filesafe::AutoBackupDay::Mon,
                "2" => server_params.auto_bu_params.day = filesafe::AutoBackupDay::Tue,
                "3" => server_params.auto_bu_params.day = filesafe::AutoBackupDay::Wed,
                "4" => server_params.auto_bu_params.day = filesafe::AutoBackupDay::Thr,
                "5" => server_params.auto_bu_params.day = filesafe::AutoBackupDay::Fri,
                "6" => server_params.auto_bu_params.day = filesafe::AutoBackupDay::Sat,
                "7" => server_params.auto_bu_params.day = filesafe::AutoBackupDay::Sun,
                _ => bail!("Invalid auto backup day"),
            };
        }
        None => (),
    };
    match matches.value_source("secondary backup") {
        Some(_) => {
            let sec_bu_dir = matches
                .get_one::<String>("secondary backup")
                .expect("Args do not contain secondary backup")
                .to_string();
            match sec_bu_dir.as_str() {
                "n" => server_params.sec_backup_dir = None,
                "N" => server_params.sec_backup_dir = None,
                "none" => server_params.sec_backup_dir = None,
                "None" => server_params.sec_backup_dir = None,
                "NONE" => server_params.sec_backup_dir = None,
                _ => {
                    ensure!(
                        Path::new(&sec_bu_dir).exists(),
                        "Secondary backup directory provided does not exist in filesystem"
                    );
                    server_params.sec_backup_dir = Some(sec_bu_dir);
                }
            };
        }
        None => (),
    };
    Ok(server_params)
}

fn parse_time(time: String) -> Result<usize> {
    let chars: Vec<char> = time.chars().collect();
    for c in chars.clone() {
        if !c.is_numeric() {
            bail!("Invalid time passed");
        }
    }
    let hours: Vec<char>;
    let mins: Vec<char>;
    match chars.len() {
        4 => {
            hours = chars[..2].to_vec();
            mins = chars[2..].to_vec();
        }
        3 => {
            hours = chars[0..1].to_vec();
            mins = chars[1..].to_vec();
        }
        _ => bail!("Invalid time passed"),
    };
    let mins: String = mins.into_iter().collect();
    let hours: String = hours.into_iter().collect();
    let mins = mins.parse::<usize>()?;
    ensure!(mins < 60, "Invalid time passed");
    let hours = hours.parse::<usize>()?;
    ensure!(hours < 24, "Invalid time passed");
    let seconds = (mins * 60) + (hours * 3600);
    Ok(seconds)
}

fn get_ip() -> Result<String> {
    let all_ifaces = interfaces();
    let default_interface = all_ifaces
        .iter()
        .filter(|e| e.is_up() && !e.is_loopback() && e.ips.len() > 0)
        .next();
    match default_interface {
        Some(interface) => {
            let v4_addr = interface
                .ips
                .iter()
                .filter(|inet| inet.is_ipv4())
                .next()
                .unwrap()
                .ip();
            return Ok(v4_addr.to_string());
        }
        None => {
            bail!("Error while finding the default interface.");
        }
    };
}

fn get_readable_size(num_bytes: u64) -> String {
    if num_bytes < 1000 {
        return format!("{}B", num_bytes);
    }
    if num_bytes < 1000000 {
        return format!("{:.1}K", num_bytes as f64 / 1000.0);
    }
    if num_bytes < 1000000000 {
        return format!("{:.1}M", num_bytes as f64 / 1000000.0);
    }
    format!("{:.1}G", num_bytes as f64 / 1000000000.0)
}

fn filesafe_setup(protected_dir: &str, secondary_backup: &Option<String>) -> Result<()> {
    let create_new = should_create_new(0)?;
    let is_unlocked = filesafe::is_unlocked(protected_dir)?;
    if create_new {
        filesafe::log_event("Creating new filesafe", filesafe::LogLevel::Info);
        if is_unlocked {
            println!("Filesafe MUST be locked to save backup. Enter password to lock filesafe.");
            lock_if_unlocked(0, protected_dir)?;
        }
        let is_locked = filesafe::is_locked()?;
        if is_locked {
            let backup = filesafe::create_backup(secondary_backup)?;
            fs::remove_dir_all(filesafe::FILESAFE_ENCRYPTED_DIR)?;
            fs::create_dir_all(filesafe::FILESAFE_ENCRYPTED_DIR)?;
            fs::remove_file(filesafe::FILESAFE_SHADOW)?;
            let event = format!("Backup created at {}", backup);
            filesafe::log_event(&event, filesafe::LogLevel::Info);
        }
        return initial_filesafe_setup();
    }
    let is_locked = filesafe::is_locked()?;
    let is_unlocked = filesafe::is_unlocked(protected_dir)?;
    if is_locked {
        filesafe::log_event("Filesafe is Locked", filesafe::LogLevel::Info)
    }
    if is_unlocked {
        filesafe::log_event("Filesafe is Unlocked", filesafe::LogLevel::Info)
    }
    Ok(())
}

fn should_create_new(mut num_tries: usize) -> Result<bool> {
    ensure!(
        num_tries < filesafe::MAX_PASS_ATTEMPT,
        "Max attempts exceeded [should_create_new]"
    );
    let mut ans = String::new();
    print!("Create new filesafe? [y/n]: ");
    let _ = io::stdout().flush();
    let _byt = io::stdin().read_line(&mut ans)?;
    let processed_ans = &ans.to_lowercase().trim().to_string();
    if processed_ans == "y" {
        return Ok(true);
    }
    if processed_ans == "n" {
        return Ok(false);
    }
    println!("Invalid input");
    num_tries += 1;
    should_create_new(num_tries)
}

fn read_file(path: &str) -> Result<String> {
    let mut s = String::new();
    let mut f = File::open(path)?;
    match f.read_to_string(&mut s) {
        Ok(_) => Ok(s),
        Err(e) => bail!("{}", e),
    }
}
