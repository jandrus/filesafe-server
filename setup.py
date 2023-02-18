#!/usr/bin/python

# Filesafe - Secure file vault
# Copyright (C) 2023 James Andrus
# Email: jandrus@citadel.edu

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

""" Filesafe server setup """


import os
import time
import configparser


HOME            = os.path.expanduser("~")
FILESAFE_DIR    = f"{HOME}/.config/filesafe/"
BANNER          = """
    _______ __                ____
   / ____(_) /__  _________ _/ __/__
  / /_  / / / _ \/ ___/ __ `/ /_/ _ \\
 / __/ / / /  __(__  ) /_/ / __/  __/
/_/   /_/_/\___/____/\__,_/_/  \___/
"""


def clear_screen():
    """ Clear terminal """
    os.system("clear")

def print_banner(section):
    """ Print banner """
    clear_screen()
    print(BANNER)
    print(f"Setup: [{section}]")

def create_dirs():
    """ Create filesafe directories """
    os.makedirs(FILESAFE_DIR, exist_ok=True)
    os.makedirs(f"{FILESAFE_DIR}.compressed/", exist_ok=True)
    os.makedirs(f"{FILESAFE_DIR}encrypted/", exist_ok=True)
    os.makedirs(f"{FILESAFE_DIR}backup/", exist_ok=True)
    print("Filesafe directories created")

def should_create_new():
    """ Create new config file """
    configuration_file = f"{FILESAFE_DIR}filesafe.ini"
    client_section = {}
    should_continue = True
    if os.path.isfile(configuration_file):
        print_banner("CONF FILE DETECTED")
        print("Previous configuration file exists. All previous SERVER settings will be erased (CLIENT settings will be preserved).")
        ans = input("Create new config (y/n): ").lower()
        if ans[0] == "y":
            print("Creating new configuration file.")
            config = configparser.ConfigParser(allow_no_value=True)
            config.read(configuration_file)
            os.remove(configuration_file)
            time.sleep(1.5)
            if "CLIENT" in config.sections():
                client_section = dict(config["CLIENT"])
        else:
            should_continue = False
            print(f"Please edit \'{configuration_file}\' manually.")
            time.sleep(1.5)
    return client_section, should_continue

def setup_conf_file():
    """ Setup conf file """
    prev_conf, should_continue = should_create_new()
    if not should_continue:
        return
    conf_file = f"{FILESAFE_DIR}filesafe.ini"
    conf = configparser.ConfigParser(allow_no_value=True)
    conf.read(conf_file)
    if "SERVER" not in conf.sections():
        conf.add_section("SERVER")
    conf.set("SERVER", "# Port server will bind to")
    conf.set("SERVER", "port", get_port())
    print("Port [OK]")
    time.sleep(1.5)
    conf.set("SERVER", "# Directory that filesafe will lock and unlock.")
    conf.set("SERVER", "# This directory MUST exist at compile time.")
    conf.set("SERVER", "protected_dir", get_protected_dir())
    print("Protected Directory [OK]")
    time.sleep(1.5)
    conf.set("SERVER", "# Time (in minutes) where server will automatically lock the protected directory.")
    conf.set("SERVER", "timeout", get_timeout())
    print("Timeout [OK]")
    time.sleep(1.5)
    conf.set("SERVER", "# Auto-backup frequency.")
    conf.set("SERVER", "# Valid options are: \'n\' (NO automatic backups), \'d\' (Daily backups), or \'w\' (Weekly backups)")
    freq = get_bu_freq()
    conf.set("SERVER", "auto_backup_freq", freq)
    print("Backup Frequency [OK]")
    time.sleep(1.5)
    backup_time = "0200"
    backup_day = "6"
    if freq != "n":
        backup_time = get_backup_time()
        print("Backup Time [OK]")
        time.sleep(1.5)
        if freq == "w":
            backup_day = get_backup_day()
            print("Backup Day [OK]")
            time.sleep(1.5)
    conf.set("SERVER", "# Time of day (24Hour clock) where automatic backup will occur")
    conf.set("SERVER", "#   Valid time format examples: 0000, 0400, 1302, 2400, 0000 (2400 == 0000)")
    conf.set("SERVER", "auto_backup_time", backup_time)
    conf.set("SERVER", "# Auto backup day of the week.")
    conf.set("SERVER", "# Valid options are 1 - 7. Only valid if auto_backup_freq is set to \'w\'.")
    conf.set("SERVER", "# 1 equates to moday and 7 equates to sunday.")
    conf.set("SERVER", "auto_backup_day", backup_day)
    conf.set("SERVER", "# Secondary backup directory. Auto backups and prompted backups will be copied to this directory.")
    conf.set("SERVER", "# Primary directory for backups will still be \'~/.config/filesafe/backup\'.")
    conf.set("SERVER", "# Provide valid full directory or \'n\' for none.")
    conf.set("SERVER", "sec_backup_dir", get_secondary_backup_dir())
    print("Secondary Backup Directory [OK]")
    time.sleep(1.5)
    conf.set("SERVER", "# Allows filesafe to shred files (shred -u file) when locking. This will cut performance significantly, but will ensure files are properly deleted and unrecoverable with forensics.")
    conf.set("SERVER", "# Not necessary if disk encryption is used.")
    conf.set("SERVER", "# \'shred\' command must be installed on server (included in most linux kernels)!!!")
    conf.set("SERVER", "# Valid values are \'y\' or \'n\'")
    conf.set("SERVER", "shred", get_shred())
    print("Shred [OK]")
    time.sleep(1.5)
    if prev_conf:
        conf.add_section("CLIENT")
        conf["CLIENT"] = prev_conf
    with open(conf_file, 'w', encoding="us-ascii") as fp:
        conf.write(fp)
    print(f"Config file saved to \'{FILESAFE_DIR}filesafe.ini\'")
    time.sleep(2)

def get_shred():
    """ Get shred """
    try:
        print_banner("shred")
        print("Shredding files overwrites files with random data upon deletion so that they cannot be recovered by forensics.")
        print("Allowing this feature significantly reduces lock/unlock time and is unnecessary if server is running on an encrypted disk.")
        print("This feature \'shreds\' (shred -u file) for files placed in the \'protected_dir\' and temporary compressed files when locking.")
        print("This feature is recommended, but can be turned off for performance.")
        ans = input("Allow shred [y/n]: ").lower()[0]
        if ans in ("y", "n"):
            print(ans)
            return ans
        print("Invalid answer.")
        time.sleep(1.5)
        return get_shred()
    except ValueError:
        print("Invalid answer.")
        time.sleep(1.5)
        return get_shred()

def get_backup_day():
    """ Get backup day """
    try:
        print_banner("auto_backup_day")
        print("Enter day of the week where automatic backups will occur.")
        print("Valid options [1 .. 7]. 1 equates to Monday, 7 to Sunday, etc...")
        day = int(input("Enter Day: "))
        if 0 < day < 8:
            print(day)
            return str(day)
        print("Invalid day.")
        time.sleep(1.5)
        return get_backup_day()
    except ValueError:
        print("Invalid day.")
        time.sleep(1.5)
        return get_backup_day()

def get_backup_time():
    """ Get backup time """
    try:
        print_banner("auto_backup_time")
        print("Enter time (24Hour clock) where automatic backup will occur. (2400 == 0000)")
        bu_time = input("Enter time: ")
        if len(bu_time) in (4, 3):
            mins = int(bu_time[-2:])
            hrs = int(bu_time[:-2])
            if mins in range(60) and hrs in range(25):
                print(bu_time)
                return bu_time
        print("Invalid time")
        time.sleep(1.5)
        return get_backup_time()
    except ValueError:
        print("Invalid time")
        time.sleep(1.5)
        return get_backup_time()

def get_secondary_backup_dir():
    """ Set secondary backup directory """
    try:
        print_banner("sec_backup_dir")
        print("Enter full path for secondary backup directory (starting at \'/\').")
        print("This is the directory that backups will be copied to (Backups are always encrypted).")
        print("Backups will still remain in \'$HOME/.config/filesafe/backup/\'")
        secondary_dir = input("Enter Directory or \'n\' for NO secondary backup: ")
        if secondary_dir.lower() == "n":
            return secondary_dir.lower()
        if secondary_dir[0] == "/" and os.path.isdir(secondary_dir):
            print(secondary_dir)
            return secondary_dir
        print("Invalid path. Path must begin at \'/\'.")
        time.sleep(1.5)
        return get_secondary_backup_dir()
    except ValueError:
        print("Invalid path. Path must begin at \'/\'.")
        return get_secondary_backup_dir()

def get_bu_freq():
    """ Get automatic backup frequency """
    try:
        print_banner("auto_backup_freq")
        print("Set backup frequency for server.")
        print("n\t-> No automatic backups")
        print("d\t-> Daily automatic backups")
        print("w\t-> Weekly automatic backups")
        freq = input("Select backup frequency: ").lower()
        if freq in ("n", "d", "w"):
            return freq
        print("Invalid input.")
        time.sleep(1.5)
        return get_bu_freq()
    except ValueError:
        print("Invalid input.")
        time.sleep(1.5)
        return get_bu_freq()

def get_timeout():
    """ Get timeout """
    try:
        print_banner("timeout")
        print("Set timeout for server (in minutes).")
        print("If the protected directory has not been modified within the timeout, then the server will automatically locked.")
        print("Minimum timeout is 5 minutes.")
        timeout = int(input("Timeout: "))
        if timeout >= 5:
            print(timeout)
            return str(timeout)
        print("Invalid timeout.")
        time.sleep(1.5)
        return get_timeout()
    except ValueError:
        print("Invalid timeout.")
        time.sleep(1.5)
        return get_timeout()

def get_protected_dir():
    """ Get protected dir for server """
    try:
        print_banner("protected_dir")
        print("Enter full path for protected directory (starting at \'/\').")
        print("This is the directory that will be locked/unlocked by the server.")
        protected_dir = input("Protected Directory: ")
        if protected_dir[0] == "/" and os.path.isdir(protected_dir):
            print(protected_dir)
            return protected_dir
        print("Invalid path. Path must begin at \'/\'.")
        time.sleep(1.5)
        return get_protected_dir()
    except ValueError:
        print("Invalid path. Path must begin at \'/\'.")
        return get_protected_dir()

def get_port():
    """ Get port for server """
    try:
        print_banner("port")
        port = int(input("Enter port number for server to bind to: "))
        if 0 < port < 65535:
            return str(port)
        print("Invalid port")
        time.sleep(1.5)
        return get_port()
    except ValueError:
        print("Invalid port")
        time.sleep(1.5)
        return get_port()


create_dirs()
setup_conf_file()
print_banner("Complete")
