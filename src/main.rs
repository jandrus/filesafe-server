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

use anyhow::{bail, ensure, Result};
use chrono::{Datelike, Local, NaiveDateTime, Timelike};
use clap::{Arg, ArgMatches, Command};
use core::time;
use rand::distributions::Alphanumeric;
use rand::Rng;
use secstr::SecStr;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::str::from_utf8;
use std::sync::{Arc, Mutex};
use std::{process, thread};
use zeroize::Zeroize;

use filesafe;

mod crypto;
mod init;

// EXIT CODES
const EX_USAGE: i32 = 64;
const EX_DATAERR: i32 = 65;
const EX_UNAVAILABLE: i32 = 69;
const EX_SOFTWARE: i32 = 70;
// REQUEST MSGS
const REQUEST_UNLOCK: &str = "601";
const REQUEST_LOCK: &str = "602";
const REQUEST_EXIT: &str = "603";
// STATUS MSGS
const STATUS_IS_LOCKED: &str = "101";
const STATUS_IS_UNLOCKED: &str = "102";
const STATUS_IS_EMPTY: &str = "103";
const STATUS_OK: &str = "200";
const STATUS_IN_ACTION: &str = "201";
const STATUS_SERVER_ERR: &str = "500";
const STATUS_AUTH_BAD: &str = "401";
const STATUS_GOOD_KEY: &str = "211";

fn main() {
    let matches = get_matches();
    clear_screen();
    let server_params = match init::setup_server_params(matches.clone()) {
        Ok(sp) => sp,
        Err(e) => {
            let err_str = format!("[Error] main::init::setup {}", e);
            filesafe::log_event(&err_str, filesafe::LogLevel::Error);
            process::exit(EX_USAGE);
        }
    };
    filesafe::log_event("Server startup", filesafe::LogLevel::Info);
    let server_keys = match crypto::gen_keys() {
        Ok(k) => k,
        Err(e) => {
            let err_str = format!("[Error] main::crypto::gen_keys {}", e);
            filesafe::log_event(&err_str, filesafe::LogLevel::Error);
            process::exit(EX_SOFTWARE);
        }
    };
    let in_action = Arc::new(Mutex::new(false));
    if matches.get_flag("setup") {
        filesafe::log_event("Begin setup", filesafe::LogLevel::Info);
        match init::setup_interractive(
            &server_params.protected_dir,
            &server_params.sec_backup_dir,
            server_params.shred_file,
        ) {
            Ok(_) => (),
            Err(e) => {
                let err_str = format!("[Error] main::init::setup_interractive {}", e);
                filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                process::exit(EX_DATAERR);
            }
        }
        let in_action_clone = Arc::clone(&in_action);
        match watch_setup_interractive(
            &server_params.protected_dir,
            server_params.timeout,
            matches.clone(),
            in_action_clone,
            server_params.shred_file.clone(),
        ) {
            Ok(_) => (),
            Err(e) => {
                let err_str = format!("[Error] main::watch_setup_interractive {}", e);
                filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                process::exit(EX_SOFTWARE);
            }
        };
    } else {
        match init::setup_non_interractive(
            &server_params.protected_dir,
            matches.clone(),
            server_params.shred_file,
        ) {
            Ok(_) => (),
            Err(e) => {
                let err_str = format!("[Error] main::init::setup_non_interractive {}", e);
                filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                process::exit(EX_USAGE);
            }
        };
        let in_action_clone = Arc::clone(&in_action);
        match watch_setup_non_interractive(
            &server_params.protected_dir,
            server_params.timeout,
            matches.clone(),
            in_action_clone,
            server_params.shred_file.clone(),
        ) {
            Ok(_) => (),
            Err(e) => {
                let err_str = format!("[Error] main::watch_setup_non_interractive {}", e);
                filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                process::exit(EX_SOFTWARE);
            }
        };
    }
    let backup_params_clone = server_params.auto_bu_params.clone();
    let secondary_backup_clone = server_params.sec_backup_dir.clone();
    thread::spawn(move || autobackup(backup_params_clone, &secondary_backup_clone));
    let ip_str = format!("{}:{}", server_params.ip, server_params.port);
    let event = format!("Attempting to bind {}", ip_str);
    filesafe::log_event(&event, filesafe::LogLevel::Info);
    let listener = match TcpListener::bind(&ip_str) {
        Ok(listener) => {
            filesafe::log_event("Server bind successful", filesafe::LogLevel::Info);
            listener
        }
        Err(e) => {
            let err_str = format!("[Error] main::tcplistener {}", e);
            filesafe::log_event(&err_str, filesafe::LogLevel::Error);
            process::exit(EX_UNAVAILABLE);
        }
    };
    let event = format!("Listening for connections on {}", &ip_str);
    filesafe::log_event(&event, filesafe::LogLevel::Info);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let event = format!("New Connection from {}", stream.peer_addr().unwrap());
                filesafe::log_event(&event, filesafe::LogLevel::Info);
                let keys_clone = server_keys.clone();
                let protected_dir_clone = server_params.protected_dir.clone();
                let in_action_clone = Arc::clone(&in_action);
                let shred_files = server_params.shred_file.clone();
                thread::spawn(move || {
                    handle_connection(
                        stream,
                        keys_clone,
                        protected_dir_clone,
                        in_action_clone,
                        shred_files,
                    )
                });
            }
            Err(e) => {
                let err_str = format!("[Error] main::incoming {}", e);
                filesafe::log_event(&err_str, filesafe::LogLevel::Error);
            }
        }
    }
    drop(listener);
}

fn handle_connection(
    stream: TcpStream,
    my_keys: crypto::Keys,
    protected_dir: String,
    in_action: Arc<Mutex<bool>>,
    shred_files: bool,
) {
    // Generate nonce
    let nonce_string: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    // Send nonce + key
    let nonce_key = format!("{}{}", nonce_string, &my_keys.pk_export);
    match send_msg(&nonce_key, &stream) {
        Ok(_) => (),
        Err(e) => {
            let err_str = format!(
                "[Error] handle::send_msg:KEY with {}: {}",
                stream.peer_addr().unwrap(),
                e
            );
            filesafe::log_event(&err_str, filesafe::LogLevel::Error);
            drop(stream);
            return;
        }
    };
    let event = format!(
        "Key exchange successful with {}",
        stream.peer_addr().unwrap()
    );
    filesafe::log_event(&event, filesafe::LogLevel::Info);
    // Did client receive nonce & key
    let msg = match recv_msg(&stream) {
        Ok(s) => s,
        Err(e) => {
            let err_str = format!(
                "[Error] handle::recv_msg:KEY with {}: {}",
                stream.peer_addr().unwrap(),
                e
            );
            filesafe::log_event(&err_str, filesafe::LogLevel::Error);
            drop(stream);
            return;
        }
    };
    if msg != STATUS_GOOD_KEY {
        let err_str = format!(
            "[Error] handle::BAD_KEY with {}",
            stream.peer_addr().unwrap(),
        );
        filesafe::log_event(&err_str, filesafe::LogLevel::Error);
        drop(stream);
        return;
    }
    // Get nonce & password from client [ENCRYPTED]
    let mut client_response = match recv_msg(&stream) {
        Ok(s) => s,
        Err(e) => {
            let err_str = format!(
                "[Error] handle::recv_msg:PASS with {}: {}",
                stream.peer_addr().unwrap(),
                e
            );
            filesafe::log_event(&err_str, filesafe::LogLevel::Error);
            drop(stream);
            return;
        }
    };
    // decrypt password
    let mut dec_response = match crypto::decrypt_msg(&client_response, my_keys.clone()) {
        Ok(s) => s,
        Err(e) => {
            let err_str = format!(
                "[Error] handle::decrypt_msg with {}: {}",
                stream.peer_addr().unwrap(),
                e
            );
            filesafe::log_event(&err_str, filesafe::LogLevel::Error);
            client_response.zeroize();
            drop(stream);
            return;
        }
    };
    client_response.zeroize();
    // is response too small
    if dec_response.len() < 9 {
        let err_str = format!(
            "[Error] handle::response length < 9 from {}",
            stream.peer_addr().unwrap()
        );
        filesafe::log_event(&err_str, filesafe::LogLevel::Error);
        dec_response.zeroize();
        drop(stream);
        return;
    }
    // place response in secure string and zeroize decrypted response
    let secure_np = SecStr::from(dec_response);
    // Verify password and nonce
    let pass_auth: bool;
    {
        let unsecure_np = from_utf8(secure_np.unsecure()).unwrap();
        let client_nonce = &unsecure_np[..8];
        let client_pass = &mut unsecure_np[8..].to_string();
        pass_auth = match crypto::verify_password(client_pass) {
            Ok(b) => b,
            Err(e) => {
                let err_str = format!(
                    "[Error] handle::verify_password with {}: {}",
                    stream.peer_addr().unwrap(),
                    e
                );
                filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                client_pass.zeroize();
                drop(stream);
                return;
            }
        };
        client_pass.zeroize();
        if nonce_string.ne(&client_nonce) {
            let event = format!("Bad nonce from {}", stream.peer_addr().unwrap());
            filesafe::log_event(&event, filesafe::LogLevel::Info);
            match send_msg(STATUS_AUTH_BAD, &stream) {
                Ok(_) => (),
                Err(e) => {
                    let err_str = format!(
                        "[Error] handle::send_msg:AUTH_BAD with {}: {}",
                        stream.peer_addr().unwrap(),
                        e
                    );
                    filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                    drop(stream);
                    return;
                }
            };
            drop(stream);
            return;
        }
    }
    if !pass_auth {
        let event = format!("Bad password from {}", stream.peer_addr().unwrap());
        filesafe::log_event(&event, filesafe::LogLevel::Info);
        match send_msg(STATUS_AUTH_BAD, &stream) {
            Ok(_) => (),
            Err(e) => {
                let err_str = format!(
                    "[Error] handle::send_msg:AUTH_BAD with {}: {}",
                    stream.peer_addr().unwrap(),
                    e
                );
                filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                drop(stream);
                return;
            }
        };
        drop(stream);
        return;
    }
    let event = format!(
        "Authentication successful from {}",
        stream.peer_addr().unwrap()
    );
    filesafe::log_event(&event, filesafe::LogLevel::Info);
    let is_locked = match filesafe::is_locked() {
        Ok(b) => b,
        Err(e) => {
            let err_str = format!(
                "[Error] handle::is_locked with {}: {}",
                stream.peer_addr().unwrap(),
                e
            );
            filesafe::log_event(&err_str, filesafe::LogLevel::Error);
            match send_msg(STATUS_SERVER_ERR, &stream) {
                Ok(_) => (),
                Err(e) => {
                    let err_str = format!(
                        "[Error] handle::send_msg:SERVER_ERR with {}: {}",
                        stream.peer_addr().unwrap(),
                        e
                    );
                    filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                }
            };
            drop(stream);
            return;
        }
    };
    let is_unlocked = match filesafe::is_unlocked(&protected_dir) {
        Ok(b) => b,
        Err(e) => {
            let err_str = format!(
                "[Error] handle::is_unlocked with {}: {}",
                stream.peer_addr().unwrap(),
                e
            );
            filesafe::log_event(&err_str, filesafe::LogLevel::Error);
            match send_msg(STATUS_SERVER_ERR, &stream) {
                Ok(_) => (),
                Err(e) => {
                    let err_str = format!(
                        "[Error] handle::send_msg:SERVER_ERR:unlock with {}: {}",
                        stream.peer_addr().unwrap(),
                        e
                    );
                    filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                }
            };
            drop(stream);
            return;
        }
    };
    if is_locked {
        match send_msg(STATUS_IS_LOCKED, &stream) {
            Ok(_) => (),
            Err(e) => {
                let err_str = format!(
                    "[Error] handle::send_msg:IS_LOCKED with {}: {}",
                    stream.peer_addr().unwrap(),
                    e
                );
                filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                drop(stream);
                return;
            }
        };
    } else if is_unlocked {
        match send_msg(STATUS_IS_UNLOCKED, &stream) {
            Ok(_) => (),
            Err(e) => {
                let err_str = format!(
                    "[Error] handle::send_msg:IS_UNLOCKED with {}: {}",
                    stream.peer_addr().unwrap(),
                    e
                );
                filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                drop(stream);
                return;
            }
        };
    } else {
        match send_msg(STATUS_IS_EMPTY, &stream) {
            Ok(_) => (),
            Err(e) => {
                let err_str = format!(
                    "[Error] handle::send_msg:IS_EMPTY with {}: {}",
                    stream.peer_addr().unwrap(),
                    e
                );
                filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                drop(stream);
                return;
            }
        };
        filesafe::log_event("Filesafe is empty", filesafe::LogLevel::Info);
        drop(stream);
        return;
    }
    let client_action = match recv_msg(&stream) {
        Ok(s) => s,
        Err(e) => {
            let err_str = format!(
                "[Error] handle::recv_msg:client_action with {}: {}",
                stream.peer_addr().unwrap(),
                e
            );
            filesafe::log_event(&err_str, filesafe::LogLevel::Error);
            drop(stream);
            return;
        }
    };
    if client_action == REQUEST_EXIT {
        let event = format!("client [{}] exit", stream.peer_addr().unwrap());
        filesafe::log_event(&event, filesafe::LogLevel::Info);
        drop(stream);
        return;
    }
    if client_action != REQUEST_LOCK && client_action != REQUEST_UNLOCK {
        let event = format!("Invalid action from {}", stream.peer_addr().unwrap());
        filesafe::log_event(&event, filesafe::LogLevel::Info);
        drop(stream);
        return;
    }
    if client_action == REQUEST_LOCK && !is_locked {
        let unsecure_np = from_utf8(secure_np.unsecure()).unwrap();
        let client_pass = &mut unsecure_np[8..].to_string();
        match lock_with_stream(
            &protected_dir,
            &client_pass,
            &stream,
            in_action,
            shred_files,
        ) {
            Ok(_) => (),
            Err(e) => {
                let err_str = format!(
                    "[Error] handle::lock_with_stream with {}: {}",
                    stream.peer_addr().unwrap(),
                    e
                );
                filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                match send_msg(STATUS_SERVER_ERR, &stream) {
                    Ok(_) => (),
                    Err(e) => {
                        let err_str = format!(
                            "[Error] handle::send_msg:SERVER_ERR:lock with {}: {}",
                            stream.peer_addr().unwrap(),
                            e
                        );
                        filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                        drop(stream);
                        client_pass.zeroize();
                        return;
                    }
                };
                client_pass.zeroize();
                drop(stream);
                return;
            }
        };
        client_pass.zeroize();
    } else if client_action == REQUEST_UNLOCK && is_locked {
        let unsecure_np = from_utf8(secure_np.unsecure()).unwrap();
        let client_pass = &mut unsecure_np[8..].to_string();
        match unlock_with_stream(
            &client_pass,
            &stream,
            &protected_dir,
            in_action,
            shred_files,
        ) {
            Ok(_) => (),
            Err(e) => {
                let err_str = format!(
                    "[Error] handle::unlock_with_stream with {}: {}",
                    stream.peer_addr().unwrap(),
                    e
                );
                filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                match send_msg(STATUS_SERVER_ERR, &stream) {
                    Ok(_) => (),
                    Err(e) => {
                        let err_str = format!(
                            "[Error] handle::send_msg:SERVER_ERR:unlock with {}: {}",
                            stream.peer_addr().unwrap(),
                            e
                        );
                        filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                        drop(stream);
                        client_pass.zeroize();
                        return;
                    }
                };
                drop(stream);
                client_pass.zeroize();
                return;
            }
        };
        client_pass.zeroize();
    } else {
        let event = format!(
            "Client [{}] requested action for current filesafe state",
            stream.peer_addr().unwrap()
        );
        filesafe::log_event(&event, filesafe::LogLevel::Info);
        drop(stream);
        return;
    }
    drop(stream);
}

fn send_msg(msg: &str, mut stream: &TcpStream) -> Result<()> {
    stream.write_all(msg.as_bytes())?;
    Ok(())
}

fn recv_msg(stream: &TcpStream) -> Result<String> {
    let mut reader = BufReader::new(stream);
    let received: Vec<u8> = reader.fill_buf().unwrap().to_vec();
    reader.consume(received.len());
    let msg = from_utf8(&received)?.to_owned();
    Ok(msg)
}

fn unlock_with_stream(
    password: &str,
    stream: &TcpStream,
    protected_dir: &str,
    in_action: Arc<Mutex<bool>>,
    shred_files: bool,
) -> Result<()> {
    let is_valid_pass = crypto::verify_password(&password)?;
    ensure!(is_valid_pass, "Invalid password received");
    {
        let mut action = match in_action.lock() {
            Ok(b) => b,
            Err(e) => {
                send_msg(STATUS_SERVER_ERR, stream)?;
                bail!("{}", e);
            }
        };
        if *action {
            let event = format!(
                "{} requested unlock while locking or unlocking",
                stream.peer_addr().unwrap()
            );
            filesafe::log_event(&event, filesafe::LogLevel::Info);
            send_msg(STATUS_IN_ACTION, &stream)?;
            return Ok(());
        } else {
            *action = true;
        }
    }
    let event = format!(
        "Unlocking filesafe from client {}",
        stream.peer_addr().unwrap(),
    );
    filesafe::log_event(&event, filesafe::LogLevel::Info);
    match crypto::unlock(&password, shred_files) {
        Ok(_) => match filesafe::restore_files(&protected_dir, shred_files) {
            Ok(_) => {
                let mut action = match in_action.lock() {
                    Ok(b) => b,
                    Err(e) => {
                        send_msg(STATUS_SERVER_ERR, stream)?;
                        bail!("{}", e);
                    }
                };
                *action = false;
                send_msg(STATUS_OK, stream)?;
            }
            Err(e) => {
                {
                    let mut action = match in_action.lock() {
                        Ok(b) => b,
                        Err(e) => {
                            send_msg(STATUS_SERVER_ERR, stream)?;
                            bail!("{}", e);
                        }
                    };
                    *action = false;
                }
                send_msg(STATUS_SERVER_ERR, stream)?;
                bail!("{}", e);
            }
        },
        Err(e) => {
            {
                let mut action = match in_action.lock() {
                    Ok(b) => b,
                    Err(e) => {
                        send_msg(STATUS_SERVER_ERR, stream)?;
                        bail!("{}", e);
                    }
                };
                *action = false;
            }
            send_msg(STATUS_SERVER_ERR, stream)?;
            bail!("{}", e);
        }
    }
    Ok(())
}

fn lock_with_stream(
    protected_dir: &str,
    password: &str,
    stream: &TcpStream,
    in_action: Arc<Mutex<bool>>,
    shred_files: bool,
) -> Result<()> {
    let event = format!("Begin lock from {} ", stream.peer_addr().unwrap());
    filesafe::log_event(&event, filesafe::LogLevel::Debug);
    let is_valid_pass = crypto::verify_password(&password)?;
    ensure!(is_valid_pass, "Invalid password received");
    {
        let mut action = match in_action.lock() {
            Ok(b) => b,
            Err(e) => {
                send_msg(STATUS_SERVER_ERR, stream)?;
                bail!("{}", e);
            }
        };
        if *action {
            let event = format!(
                "{} requested lock while locking or unlocking",
                stream.peer_addr().unwrap()
            );
            filesafe::log_event(&event, filesafe::LogLevel::Info);
            send_msg(STATUS_IN_ACTION, &stream)?;
            let event = format!("End lock from {} BUSY", stream.peer_addr().unwrap());
            filesafe::log_event(&event, filesafe::LogLevel::Debug);
            return Ok(());
        } else {
            *action = true;
        }
    }
    let event = format!(
        "Locking filesafe from client {}",
        stream.peer_addr().unwrap(),
    );
    filesafe::log_event(&event, filesafe::LogLevel::Info);
    match crypto::lock(&password, protected_dir, shred_files) {
        Ok(_) => {
            let mut action = match in_action.lock() {
                Ok(b) => b,
                Err(e) => {
                    send_msg(STATUS_SERVER_ERR, stream)?;
                    bail!("{}", e);
                }
            };
            *action = false;
            send_msg(STATUS_OK, stream)?;
        }
        Err(e) => {
            {
                let mut action = match in_action.lock() {
                    Ok(b) => b,
                    Err(e) => {
                        send_msg(STATUS_SERVER_ERR, stream)?;
                        bail!("{}", e);
                    }
                };
                *action = false;
            }
            send_msg(STATUS_SERVER_ERR, stream)?;
            bail!("{}", e);
        }
    }
    let event = format!("End lock from {} ", stream.peer_addr().unwrap());
    filesafe::log_event(&event, filesafe::LogLevel::Debug);
    Ok(())
}

fn clear_screen() {
    print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
}

fn get_matches() -> ArgMatches {
    Command::new("filesafe-server")
        .about("Filesafe server program")
        .version("0.1.0")
        .author("Zero Cool")
        .arg_required_else_help(false)
        .arg(
            Arg::new("setup")
                .short('s')
                .long("setup")
                .help("Setup filesafe including lock/unlock, backup/restore, and initialize new filesafe-server")
                .conflicts_with("lock")
                .conflicts_with("unlock")
                .required(false)
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("unlock")
                .short('u')
                .long("unlock")
                .help("Unlock filesafe on startup if initially locked")
                .conflicts_with("lock")
                .required(false)
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("lock")
                .short('l')
                .long("lock")
                .help("Lock filesafe on startup if initially unlocked")
                .conflicts_with("unlock")
                .required(false)
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .help("Specify port for server")
                .required(false)
                .action(clap::ArgAction::Set)
                .num_args(1),
        )
        .arg(
            Arg::new("address")
                .short('a')
                .long("address")
                .help("Specify address for server")
                .required(false)
                .action(clap::ArgAction::Set)
                .num_args(1),
        )
        .arg(
            Arg::new("directory")
                .short('P')
                .long("protected")
                .help("Specify protected directory for server to encrypt/decrypt. MUST BE full filepath.")
                .required(false)
                .action(clap::ArgAction::Set)
                .num_args(1),
        )
        .arg(
            Arg::new("conf")
                .short('c')
                .long("conf")
                .help("Specify configuration file for filesafe server")
                .required(false)
                .action(clap::ArgAction::Set)
                .num_args(1),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .help("Specify timeout (interval for filesafe to auto-lock with no activity) for filesafe. In minutes (10 min minimum)")
                .required(false)
                .action(clap::ArgAction::Set)
                .num_args(1),
        )
        .arg(
            Arg::new("pass")
                .long("pass")
                .help("Specify password. Note: Use of this arg is not recommended, but is included for use with scripts")
                .required(false)
                .action(clap::ArgAction::Set)
                .num_args(1),
        )
        .arg(
            Arg::new("no timeout")
                .long("noautolock")
                .help("Disable autolocking capability. Filesafe will not lock itself after timeout.")
                .required(false)
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("backup frequency")
                .short('f')
                .long("backupfreq")
                .help("Frequency at which automatic backups are taken of filesafe. Valid options: n (NO automatic backups), d (Daily), or w (Weekly)")
                .required(false)
                .action(clap::ArgAction::Set)
                .num_args(1),
        )
        .arg(
            Arg::new("backup time")
                .short('T')
                .long("backuptime")
                .help("Time of day (24Hour clock) where automatic backup will occur. Only valid if auto_backup_freq is set to d or w.")
                .required(false)
                .action(clap::ArgAction::Set)
                .num_args(1),
        )
        .arg(
            Arg::new("backup day")
                .short('d')
                .long("backupday")
                .help("Auto backup day of the week. Only valid if auto_backup_freq is set to  w. Valid options are 1 - 7 with 1 == Monday and 7 == Sunday")
                .required(false)
                .action(clap::ArgAction::Set)
                .num_args(1),
        )
        .arg(
            Arg::new("secondary backup")
                .short('b')
                .long("backupdir")
                .help("Secondary directory for backups to be copied to. Provide full path or n for none.")
                .required(false)
                .action(clap::ArgAction::Set)
                .num_args(1),
        )
        .arg(
            Arg::new("shred")
                .short('S')
                .long("shred")
                .help("No args. If flag is given, files will be shred rather than removed.")
                .required(false)
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches()
}

fn watch(
    protected_dir: String,
    password: String,
    timeout: usize,
    lock_now: bool,
    in_action: Arc<Mutex<bool>>,
    shred_files: bool,
) {
    let pw = SecStr::from(password);
    if !lock_now {
        let sleep_time = time::Duration::from_secs(timeout as u64);
        thread::sleep(sleep_time);
    }
    let sleep_time = time::Duration::from_secs(30);
    loop {
        let is_unlocked = match filesafe::is_unlocked(&protected_dir) {
            Ok(b) => b,
            Err(_) => {
                thread::sleep(sleep_time);
                continue;
            }
        };
        let server_in_action: bool;
        {
            server_in_action = match in_action.lock() {
                Ok(b) => *b,
                Err(e) => {
                    let err_str = format!("[Error] watch::server_in_action {}", e);
                    filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                    return;
                }
            };
        }
        if is_unlocked && !server_in_action {
            let min = match get_directory_modified(&protected_dir) {
                Ok(u) => u,
                Err(e) => {
                    let err_str = format!("[Error] watch::get_directory_modified {}", e);
                    filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                    continue;
                }
            };
            if min >= (timeout as u64 * 60) {
                {
                    let mut action = match in_action.lock() {
                        Ok(b) => b,
                        Err(e) => {
                            let err_str = format!("[Error] watch::action:true {}", e);
                            filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                            return;
                        }
                    };
                    *action = true;
                }
                filesafe::log_event("Locking filesafe due to timeout", filesafe::LogLevel::Info);
                match crypto::lock(
                    from_utf8(pw.unsecure()).unwrap(),
                    &protected_dir,
                    shred_files,
                ) {
                    Ok(_) => (),
                    Err(e) => {
                        let err_str = format!("[Error] watch::lock {}", e);
                        filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                        return;
                    }
                };
            }
            {
                let mut action = match in_action.lock() {
                    Ok(b) => b,
                    Err(e) => {
                        let err_str = format!("[Error] watch::action:false {}", e);
                        filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                        return;
                    }
                };
                *action = false;
            }
        }
        thread::sleep(sleep_time);
    }
}

fn watch_setup_non_interractive(
    protected_dir: &str,
    timeout: usize,
    matches: ArgMatches,
    in_action: Arc<Mutex<bool>>,
    shred_files: bool,
) -> Result<()> {
    if matches.get_flag("no timeout") {
        filesafe::log_event("Timeout disabled by user", filesafe::LogLevel::Info);
        return Ok(());
    }
    let protected_dir_clone = protected_dir.to_string().clone();
    let timeout_clone = timeout.clone();
    match matches.value_source("pass") {
        Some(_) => {
            let pass = matches
                .get_one::<String>("pass")
                .expect("Password arg does not exist")
                .to_string();
            let is_valid_pass = crypto::verify_password(&pass)?;
            ensure!(is_valid_pass, "Invalid password passed via args");
            filesafe::log_event("Valid password received", filesafe::LogLevel::Info);
            thread::spawn(move || {
                watch(
                    protected_dir_clone,
                    pass,
                    timeout_clone,
                    true,
                    in_action,
                    shred_files,
                )
            });
        }
        None => {
            let pass = get_pass(0)?;
            thread::spawn(move || {
                watch(
                    protected_dir_clone,
                    pass,
                    timeout_clone,
                    true,
                    in_action,
                    shred_files,
                )
            });
        }
    };
    filesafe::log_event("Timeout enabled", filesafe::LogLevel::Info);
    Ok(())
}

fn watch_setup_interractive(
    protected_dir: &str,
    timeout: usize,
    matches: ArgMatches,
    in_action: Arc<Mutex<bool>>,
    shred_files: bool,
) -> Result<()> {
    if matches.get_flag("no timeout") {
        filesafe::log_event("Timeout disabled by user", filesafe::LogLevel::Info);
        return Ok(());
    }
    let protected_dir_clone = protected_dir.to_string().clone();
    let timeout_clone = timeout.clone();
    let min = get_directory_modified(protected_dir)?;
    let is_unlocked = filesafe::is_unlocked(&protected_dir)?;
    let mut allow_lock = false;
    if min < (timeout as u64 * 60) && is_unlocked {
        println!("Server will automatically lock filesafe due to modification time of the Protected directory.");
        allow_lock = should_allow_lock(0)?;
    }
    match matches.value_source("pass") {
        Some(_) => {
            let pass = matches
                .get_one::<String>("pass")
                .expect("Password arg does not exist")
                .to_string();
            let is_valid_pass = crypto::verify_password(&pass)?;
            ensure!(is_valid_pass, "Invalid password passed via args");
            filesafe::log_event("Valid password received", filesafe::LogLevel::Info);
            thread::spawn(move || {
                watch(
                    protected_dir_clone,
                    pass,
                    timeout_clone,
                    allow_lock,
                    in_action,
                    shred_files,
                )
            });
        }
        None => {
            let pass = get_pass(0)?;
            thread::spawn(move || {
                watch(
                    protected_dir_clone,
                    pass,
                    timeout_clone,
                    allow_lock,
                    in_action,
                    shred_files,
                )
            });
        }
    };
    filesafe::log_event("Timeout enabled", filesafe::LogLevel::Info);
    Ok(())
}

fn should_allow_lock(mut num_tries: usize) -> Result<bool> {
    ensure!(
        num_tries < filesafe::MAX_PASS_ATTEMPT,
        "Max attempts exceeded [should_allow_lock]"
    );
    let mut ans = String::new();
    print!("Allow filesafe to lock now? [y/n]: ");
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
    should_allow_lock(num_tries)
}

fn get_pass(mut num_tries: usize) -> Result<String> {
    ensure!(
        num_tries < filesafe::MAX_PASS_ATTEMPT,
        "Max attempts exceeded [get_pass]"
    );
    let pw = rpassword::prompt_password("Enter filesafe password (for timeout): ")?;
    let is_valid_pass = crypto::verify_password(&pw)?;
    if is_valid_pass {
        filesafe::log_event("Valid password received", filesafe::LogLevel::Info);
        return Ok(pw);
    }
    filesafe::log_event("Invalid password recieved", filesafe::LogLevel::Info);
    num_tries += 1;
    get_pass(num_tries)
}

fn get_directory_modified(dir: &str) -> Result<u64> {
    let directory = fs::read_dir(dir)?;
    let mut times: Vec<u64> = Vec::new();
    for entry in directory {
        let entry = entry?;
        let path = entry.path();
        if path.is_symlink() {
            continue;
        }
        let metadata = fs::metadata(&path)?;
        if metadata.is_dir() {
            let dir = match path.to_str() {
                Some(s) => s,
                None => continue,
            };
            let t = get_directory_modified(dir)?;
            let t_dir = metadata.modified()?.elapsed()?.as_secs();
            times.append(&mut vec![t, t_dir]);
        } else {
            let last_modified = metadata.modified()?.elapsed()?.as_secs();
            times.append(&mut vec![last_modified]);
        }
    }
    let min = match times.iter().min() {
        Some(m) => m,
        None => &(100000 as u64),
    };
    Ok(*min)
}

fn autobackup(backup_params: filesafe::AutoBackup, secondary_backup: &Option<String>) {
    match backup_params.frequency {
        filesafe::AutoBackupFrequency::None => return,
        _ => filesafe::log_event("Automatic backup enabled", filesafe::LogLevel::Info),
    };
    loop {
        let now_ts = Local::now().timestamp() - 18000;
        let now = NaiveDateTime::from_timestamp_opt(now_ts, 0).unwrap();
        let seconds = match backup_params.frequency {
            filesafe::AutoBackupFrequency::Daily => (backup_params.time as i64
                - now.num_seconds_from_midnight() as i64)
                .rem_euclid(86400),
            filesafe::AutoBackupFrequency::Weekly => {
                let weekday = now.weekday();
                let day = match weekday {
                    chrono::Weekday::Mon => 0,
                    chrono::Weekday::Tue => 1,
                    chrono::Weekday::Wed => 2,
                    chrono::Weekday::Thu => 3,
                    chrono::Weekday::Fri => 4,
                    chrono::Weekday::Sat => 5,
                    chrono::Weekday::Sun => 6,
                };
                let this_time = (day * 86400) + now.num_seconds_from_midnight() as usize;
                let wanted_time = match backup_params.day {
                    filesafe::AutoBackupDay::Mon => backup_params.time,
                    filesafe::AutoBackupDay::Tue => (1 * 86400) + backup_params.time,
                    filesafe::AutoBackupDay::Wed => (2 * 86400) + backup_params.time,
                    filesafe::AutoBackupDay::Thr => (3 * 86400) + backup_params.time,
                    filesafe::AutoBackupDay::Fri => (4 * 86400) + backup_params.time,
                    filesafe::AutoBackupDay::Sat => (5 * 86400) + backup_params.time,
                    filesafe::AutoBackupDay::Sun => (6 * 86400) + backup_params.time,
                    _ => return,
                };
                (wanted_time as i64 - this_time as i64).rem_euclid(604800)
            }
            _ => return,
        };
        let sleep_time = time::Duration::from_secs(seconds as u64);
        thread::sleep(sleep_time);
        let is_locked = match filesafe::is_locked() {
            Ok(b) => b,
            Err(e) => {
                let err_str = format!("Error autobackup::is_locked {}", e);
                filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                process::exit(EX_SOFTWARE);
            }
        };
        if is_locked {
            match filesafe::create_backup(secondary_backup) {
                Ok(s) => {
                    let event = format!("Automatic backup created {}", s);
                    filesafe::log_event(&event, filesafe::LogLevel::Info);
                }
                Err(e) => {
                    let err_str = format!("Error autobackup::create_backup {}", e);
                    filesafe::log_event(&err_str, filesafe::LogLevel::Error);
                    process::exit(EX_SOFTWARE);
                }
            }
        } else {
            filesafe::log_event(
                "Automatic backup attempted, filesafe was unlocked",
                filesafe::LogLevel::Info,
            );
            let sleep_time = time::Duration::from_secs(60 as u64);
            thread::sleep(sleep_time);
        }
    }
}
