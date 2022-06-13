// Copyright 2020-2022 Yang Hongbo, Qingdao IotPi Information Technology, Ltd.
// This file is part of libimobiledeivce.
// libimobiledevice-rs is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
// libimobiledevice-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with libimobiledevice-rs. If not, see <https://www.gnu.org/licenses/>.

use clap::{
    crate_authors, crate_name, crate_version, App, AppSettings, Arg, ArgMatches, SubCommand,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{self, prelude::*};
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::{thread, time};

use anyhow::{anyhow, Result};
use chrono::prelude::*;
use libc;
use uuid::Uuid;

use libimobiledevice::{
    afc::{AfcClient, AfcError, FileHandle as AfcFileHandle},
    ffi::{self, idevice_options},
    idevice::Device,
    installation_proxy::{ClientOptions, InstproxyClient, OptionsType},
    lockdownd::LockdowndClient,
    mobilebackup2::{
        Mobilebackup2Client, Mobilebackup2Error, Mobilebackup2Result, ReceivedMessage,
    },
    notification_proxy::{NpClient, NpClientTrait},
};

use libplist::plist::{IterDict, Plist};

const CODE_SUCCESS: u8 = 0x00;
const CODE_ERROR_LOCAL: u8 = 0x06;
const CODE_ERROR_REMOTE: u8 = 0x0b;
const CODE_FILE_DATA: u8 = 0x0c;

const ITUNES_RESTORE_DIR: &'static str = "/iTunesRestore";
const ITUNES_RESTORE_RESTORE_APPLICATION_PLIST_FILE: &'static str =
    "/iTunesRestore/RestoreApplications.plist";

fn main() -> Result<()> {
    // let dt_20010101 = Utc.ymd(2001, 1, 1).and_hms(0, 0, 0);
    // println!("dt: {:?}", dt_20010101);

    // println!("timestamp: {:?}", dt_20010101.timestamp());

    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about("idevice backup status")
        .arg(
            Arg::with_name("domain")
                .short("q")
                .value_name("domain")
                .help("set domain of query to NAME. Default: None")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("key")
                .short("k")
                .value_name("key")
                .help("only query key specified by NAME. Default: All keys.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("debug")
                .short("d")
                .long("debug")
                .help("enable communication debug (inside libimobiledevice)"),
        )
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("backup")
                .about("start backup service")
                .arg(
                    Arg::with_name("full")
                        .long("full")
                        .help("force full backup from device."),
                )
                .arg(Arg::with_name("path").takes_value(true))
                .arg(
                    Arg::with_name("udid")
                        .short("u")
                        .value_name("udid")
                        .help("target specific device by UDID")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("source_udid")
                        .short("s")
                        .long("source")
                        .value_name("source_udid")
                        .help("source identifier of backup data?")
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("restore")
                .about("start restore service")
                .arg(Arg::with_name("path").takes_value(true))
                .arg(
                    Arg::with_name("udid")
                        .short("u")
                        .value_name("udid")
                        .help("target specific device by UDID")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("source_udid")
                        .short("s")
                        .long("source")
                        .value_name("source_udid")
                        .help("source identifier of backup data?")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("system")
                        .long("system")
                        .help("restore system files, too")
                        .takes_value(false),
                )
                .arg(
                    Arg::with_name("settings")
                        .long("settings")
                        .help("restore device settings from the backup")
                        .takes_value(false),
                )
                .arg(
                    Arg::with_name("no-reboot")
                        .long("no-reboot")
                        .help("do NOT reboot the device when done (default: yes)")
                        .takes_value(false),
                )
                .arg(
                    Arg::with_name("copy")
                        .long("copy")
                        .help("create a copy of backup folder before restoring")
                        .takes_value(false),
                )
                .arg(
                    Arg::with_name("remove")
                        .long("remove")
                        .help("remove items which are not being restored")
                        .takes_value(false),
                )
                .arg(
                    Arg::with_name("skip-apps")
                        .long("skip-apps")
                        .help("do not trigger re-installation of apps after restore")
                        .takes_value(false),
                ),
        )
        .get_matches();

    // let udid = matches.value_of("udid");
    // let domain = matches.value_of("domain");
    // let key = matches.value_of("key");

    let debug: bool = matches.is_present("debug");
    if debug {
        println!("debug");
        unsafe { ffi::idevice_set_debug_level(1) };
    }

    if let Some(matches) = matches.subcommand_matches("backup") {
        let result = start_backup(&matches, debug);
        println!("start backup result: {:?}", result);
    } else if let Some(matches) = matches.subcommand_matches("restore") {
        start_restore(&matches, debug)?;
    }

    Ok(())
}

fn start_restore(matches: &ArgMatches, debug: bool) -> Result<()> {
    println!("args: {:?}", matches);

    let udid = matches.value_of("udid");
    // source_udid is required
    let source_udid = matches.value_of("source_udid").unwrap();

    let path = matches.value_of("path").ok_or(anyhow!("No Path"))?;

    let backup_root_directory_path = PathBuf::from(path);
    println!(
        "backup root directory path: {:?}",
        backup_root_directory_path
    );

    // 1. check for existence of Info.plist
    let mut info_plist_path = backup_root_directory_path.clone();
    info_plist_path.push(&source_udid);
    info_plist_path.push("Info.plist");
    let info_plist_path = info_plist_path;
    if !info_plist_path.exists() {
        panic!("{:?} does not exist", info_plist_path);
    }
    let mut file = File::open(info_plist_path)?;
    let info_plist = Plist::from(&mut file)?;

    // 2. check for Manifest.plist
    let mut manifest_plist_path = backup_root_directory_path.clone();
    manifest_plist_path.push(&source_udid);
    manifest_plist_path.push("Manifest.plist");
    let manifest_plist_path = manifest_plist_path;
    if !manifest_plist_path.exists() {
        panic!("{:?} does not exist", manifest_plist_path);
    }

    // 3. read Manifest.plist
    let mut file = File::open(manifest_plist_path)?;
    let manifest_plist = Plist::from(&mut file)?;

    // 4. check IsEncrypted in Manifest.plist
    let _is_encrypted = manifest_plist
        .dict_get_item("IsEncrypted")
        .ok_or(anyhow!("failed to get IsEncrypted from Manifest.plist",))?;
    let _is_encrypted = _is_encrypted
        .bool_value()
        .ok_or(anyhow!("failed to get bool value of IsEncrypted"))?;

    // 5. connect to lockdownd (same to backup)
    let device = Rc::new(Device::new_with_options(
        udid,
        idevice_options::IDEVICE_LOOKUP_USBMUX,
    )?);
    let lockdownd_client = LockdowndClient::new_with_handshake(device.clone(), crate_name!())?;

    let udid_str: String;
    if let Some(udid) = udid {
        udid_str = String::from(udid);
    } else {
        udid_str = device.get_udid()?
    }

    let info_target_udid = info_plist
        .dict_get_item("Target Identifier")
        .ok_or(anyhow!("failed to retrieve 'Target Identifier'"))?;
    let info_target_udid = info_target_udid.string_value().ok_or(anyhow!(
        "failed to extract 'Target Identifier' into string value"
    ))?;
    if info_target_udid != source_udid {
        return Err(anyhow!(
            "source({}) is not same as Target Indentifier({}) inside Info.plist",
            source_udid,
            info_target_udid
        ));
    }

    // 6. check for "WillEncrypt" (same to backup)
    let will_encrypt_plist =
        lockdownd_client.get_value(Some("com.apple.mobile.backup"), Some("WillEncrypt"));
    println!("{:?}", will_encrypt_plist);

    // 7. check for ProductVersion (same to backup)
    let product_version = lockdownd_client.get_value(None, Some("ProductVersion"));
    println!("ProductVersion: {:?}", product_version);

    let product_version: Option<String> =
        product_version.map_or(None, |v| v.map_or(None, |v| v.string_value()));
    println!("ProductVersion: {:?}", product_version);

    // 8. start lockdownd service (same to backup)
    // 9. start AFC service (same to backup)
    // 10. start mobilebackup2 service (same to backup)
    // 11. create mobilebackup2 client (same to backup)
    // 12. exchange mobilebackup2 version (same to backup)
    // 13. read Info.plist (same to backup)
    // 14. post notification NP_SYNC_WILL_START and afc_file_open (same to backup)
    // 15. lock file (same to backup)
    let (mobilebackup2_client, afc_client, np_client, afc_lock_handle) =
        pre_start_service(&lockdownd_client, device.clone())?;

    // 16. check Status.plist / snapshot status
    let mut status_plist_path = backup_root_directory_path.clone();
    status_plist_path.push(source_udid);
    status_plist_path.push("Status.plist");
    let status_plist_path = status_plist_path;
    if !status_plist_path.exists() {
        panic!("{:?} does not exist", status_plist_path);
    }

    let mut file = File::open(status_plist_path)?;
    let plist = Plist::from(&mut file)?;
    let snapshot_state = plist
        .dict_get_item("SnapshotState")
        .ok_or(anyhow!("failed to get SnapshotState in Status.plist"))?;
    let snapshot_state = snapshot_state
        .string_value()
        .ok_or(anyhow!("cannot read SnapshotState from Status.plist"))?;

    if snapshot_state != "finished" {
        return Err(anyhow!("This snapshot is not finished"));
    }
    // 17. setup restore options
    if !matches.is_present("skip-apps") {
        write_restore_applications(&info_plist, &afc_client)?;
    }

    let mut opts = Plist::new_dict().ok_or(anyhow!("failed to new plist dict"))?;

    let key = "RestoreSystemFiles"; // include Photos, etc
    let system = matches.is_present("system");
    let value = Plist::new_bool(system).ok_or(anyhow!("failed to new plist bool for {}", key))?;
    opts.dict_set_item(key, value);

    let key = "RestoreShouldReboot";
    let no_reboot = matches.is_present("no-reboot");
    let value =
        Plist::new_bool(!no_reboot).ok_or(anyhow!("failed to new plist bool for {}", key))?;
    opts.dict_set_item(key, value);

    let key = "RestoreDontCopyBackup";
    let copy = matches.is_present("copy");
    let value = Plist::new_bool(!copy).ok_or(anyhow!("failed to new plist bool for {}", key))?;
    opts.dict_set_item(key, value);

    let key = "RestorePreserveSettings";
    let settings = matches.is_present("settings");
    let value = Plist::new_bool(settings).ok_or(anyhow!("failed to new plist bool for {}", key))?;
    opts.dict_set_item(key, value);

    let key = "RemoveItemsNotRestored";
    let remove = matches.is_present("remove");
    let value = Plist::new_bool(remove).ok_or(anyhow!("failed to new plist bool for {}", key))?;
    opts.dict_set_item(key, value);

    // 18. start restore
    mobilebackup2_client.send_request("Restore", &udid_str, Some(&source_udid), Some(&opts))?;

    // 19. restore / message handling loop (share loop code to backup)
    let result = handle_process_loop(
        &mobilebackup2_client,
        np_client.clone(),
        &backup_root_directory_path,
        Some(afc_lock_handle),
        debug,
    );
    if result.is_err() {
        // failed to restore, then remove /iTunesRestore/
        let _ = afc_client.remove_path(ITUNES_RESTORE_RESTORE_APPLICATION_PLIST_FILE);
        let _ = afc_client.remove_path(ITUNES_RESTORE_DIR);
    }

    // force drop sequence
    // checked dop sequence by adding println! to related fn drop
    // but still has some communication error before sending
    // DLMessageDisconnect message
    drop(lockdownd_client);
    drop(mobilebackup2_client);
    drop(afc_client);
    drop(np_client);
    drop(device);

    result
}

pub fn start_backup(matches: &ArgMatches, debug: bool) -> Result<()> {
    println!("args: {:?}", matches);

    let path = matches.value_of("path").ok_or(anyhow!("No Path"))?;

    let backup_root_directory_path = Path::new(path);
    println!(
        "backup root directory path: {:?}",
        backup_root_directory_path
    );

    let udid = matches.value_of("udid");
    let domain = matches.value_of("domain");
    let key = matches.value_of("key");
    let source_udid = matches.value_of("source_udid");

    let device = Rc::new(Device::new_with_options(
        udid,
        idevice_options::IDEVICE_LOOKUP_USBMUX | idevice_options::IDEVICE_LOOKUP_NETWORK,
    )?);
    let lockdownd_client = LockdowndClient::new_with_handshake(device.clone(), crate_name!())?;
    let _plist = lockdownd_client.get_value(domain, key)?;

    let udid_str: String;
    if let Some(udid) = udid {
        udid_str = String::from(udid);
    } else {
        udid_str = device.get_udid()?
    }

    let source_udid_str: String;
    if let Some(udid) = source_udid {
        source_udid_str = String::from(udid);
    } else {
        source_udid_str = udid_str.clone();
    }

    println!(
        "udid: {}, source_udid: {}",
        udid_str.as_str(),
        source_udid_str.as_str()
    );

    let mut target_backup_directory_path = PathBuf::from(backup_root_directory_path);
    target_backup_directory_path.push(source_udid_str.as_str());
    let target_backup_directory_path = target_backup_directory_path;

    let mut info_plist_path = target_backup_directory_path.clone();
    info_plist_path.push("Info.plist");
    let info_plist_path = info_plist_path;

    let will_encrypt_plist =
        lockdownd_client.get_value(Some("com.apple.mobile.backup"), Some("WillEncrypt"));
    println!("{:?}", will_encrypt_plist);

    let will_encrypt_plist = will_encrypt_plist.map_or(false, |v| {
        v.map_or(false, |v| v.bool_value().unwrap_or(false))
    });

    println!("will_encrypt_plist: {:?}", will_encrypt_plist);

    let product_version = lockdownd_client.get_value(None, Some("ProductVersion"));
    println!("ProductVersion: {:?}", product_version);

    let product_version: Option<String> =
        product_version.map_or(None, |v| v.map_or(None, |v| v.string_value()));
    println!("ProductVersion: {:?}", product_version);

    let (mobilebackup2_client, afc_client, np_client, afc_lock_handle) =
        pre_start_service(&lockdownd_client, device.clone())?;

    println!("Starting backup...");
    // fs::DirBuilder::new()
    //     .recursive(true)
    //     .create(&target_backup_directory_path)?;

    let info_plist =
        mobilebackup_factory_info_plist_new(udid_str.as_str(), device.clone(), &afc_client)?;
    if debug {
        println!("info_plist: {:#?}", info_plist);
    }

    let data = info_plist.to_xml().ok_or(anyhow!(format!(
        "failed to generate xml format({} @ {}",
        std::file!(),
        std::line!()
    )))?;
    let mut file = File::create(info_plist_path)?;
    file.write(&data[..])?;

    println!("Requesting backup from device...");

    mobilebackup2_client.send_request("Backup", &udid_str, Some(&source_udid_str), None)?;

    let result = handle_process_loop(
        &mobilebackup2_client,
        np_client.clone(),
        &backup_root_directory_path,
        Some(afc_lock_handle),
        debug,
    );

    // force drop sequence
    drop(lockdownd_client);
    drop(mobilebackup2_client);
    drop(afc_client);
    drop(np_client);
    drop(device);

    result
}

fn pre_start_service(
    lockdownd_client: &LockdowndClient,
    device: Rc<Device>,
) -> Result<(Mobilebackup2Client, AfcClient, Rc<NpClient>, AfcFileHandle)> {
    let service = lockdownd_client.start_service(ffi::NP_SERVICE_NAME)?;

    let np_client = Rc::new(NpClient::new(device.clone(), &service)?);

    let error = np_client.set_notify_callback(|notification| {
        println!("notification inside closure: {}", notification);
    });

    println!("set_notify_callback: {:?}", error);

    let notification_spec: &[&[u8]] = &[
        ffi::NP_SYNC_CANCEL_REQUEST,
        ffi::NP_SYNC_SUSPEND_REQUEST,
        ffi::NP_SYNC_RESUME_REQUEST,
        ffi::NP_BACKUP_DOMAIN_CHANGED,
    ];
    let error = np_client.observe_notifications(notification_spec);
    println!("observe_notification: {:?}", error);

    let service = lockdownd_client.start_service(ffi::AFC_SERVICE_NAME)?;
    let afc_client = AfcClient::new(&device, &service)?;

    let service =
        lockdownd_client.start_service_with_escrow_bag(ffi::MOBILEBACKUP2_SERVICE_NAME)?;
    let mobilebackup2_client = Mobilebackup2Client::new(device.clone(), &service)?;
    let local_versions: &[f64] = &[2.0, 2.1];
    let remote_version = mobilebackup2_client.version_exchange(local_versions)?;

    println!("mobile2backup remote version: {}", remote_version);

    do_post_notification(np_client.clone(), ffi::NP_SYNC_WILL_START)?;

    let lock_path = "/com.apple.itunes.lock_sync";
    let afc_lock_handle = afc_client.file_open(&lock_path, ffi::afc_file_mode_t::AFC_FOPEN_RW)?;

    do_post_notification(np_client.clone(), ffi::NP_SYNC_LOCK_REQUEST)?;

    const LOCK_ATTEMPTS: u32 = 50;
    const LOCK_WAIT: u64 = 200;
    let mut locked = false;

    // TODO: not a good logic. can I wrap/hide handle in a struct, and hide loop detail in some structure?
    for _ in 0..LOCK_ATTEMPTS {
        let rst = afc_lock_handle.lock(ffi::afc_lock_op_t::AFC_LOCK_EX);
        match rst {
            Ok(_) => {
                locked = true;
                break;
            }
            Err(AfcError(ffi::afc_error_t::AFC_E_OP_WOULD_BLOCK)) => {
                thread::sleep(time::Duration::from_millis(LOCK_WAIT));
            }
            Err(AfcError(_other)) => {
                break;
            }
        }
    }

    if !locked {
        return Err(anyhow!(format!(
            "ERROR: could not lock file! error code: {:?}",
            ffi::afc_error_t::AFC_E_INTERNAL_ERROR
        )));
    }

    do_post_notification(np_client.clone(), ffi::NP_SYNC_DID_START)?;

    Ok((mobilebackup2_client, afc_client, np_client, afc_lock_handle))
}

fn handle_process_loop(
    mobilebackup2_client: &Mobilebackup2Client,
    np_client: Rc<NpClient>,
    backup_root_directory_path: &Path,
    lock_file_handle: Option<AfcFileHandle>,
    debug: bool,
) -> Result<()> {
    let result = process_loop(mobilebackup2_client, backup_root_directory_path, debug);

    if let Some(handle) = lock_file_handle {
        handle.lock(ffi::afc_lock_op_t::AFC_LOCK_UN)?;
        do_post_notification(np_client.clone(), ffi::NP_SYNC_DID_FINISH)?;
    }

    result
}

fn process_loop(
    mobilebackup2_client: &Mobilebackup2Client,
    backup_root_directory_path: &Path,
    debug: bool,
) -> Result<()> {
    loop {
        println!("receiving message ...");
        let result = mobilebackup2_client.receive_message();
        match result {
            Ok(message) => {
                if debug {
                    println!("message: {:#?}", message);
                }

                match message {
                    ReceivedMessage::UploadFiles(ref plist) => {
                        mb2_handle_receive_files_message(
                            &mobilebackup2_client,
                            plist,
                            &backup_root_directory_path,
                        )?;
                    }
                    ReceivedMessage::DownloadFiles(ref plist) => {
                        mb2_handle_send_files(
                            &mobilebackup2_client,
                            plist,
                            &backup_root_directory_path,
                        )?;
                    }
                    ReceivedMessage::ContentsOfDirectory(ref plist) => {
                        mb2_handle_contents_of_directory_message(
                            &mobilebackup2_client,
                            plist,
                            &backup_root_directory_path,
                        )?;
                    }
                    ReceivedMessage::GetFreeDiskSpace => {
                        mb2_handle_get_free_space(
                            &mobilebackup2_client,
                            &backup_root_directory_path,
                        )?;
                    }
                    ReceivedMessage::CreateDirectory(ref plist) => {
                        mb2_handle_create_directory_message(
                            &mobilebackup2_client,
                            plist,
                            &backup_root_directory_path,
                        )?;
                    }
                    ReceivedMessage::MoveFiles(ref plist)
                    | ReceivedMessage::MoveItems(ref plist) => {
                        mb2_handle_move_files_message(
                            &mobilebackup2_client,
                            plist,
                            &backup_root_directory_path,
                        )?;
                    }
                    ReceivedMessage::RemoveFiles(ref plist)
                    | ReceivedMessage::RemoveItems(ref plist) => {
                        mb2_handle_remove_item_message(
                            &mobilebackup2_client,
                            plist,
                            &backup_root_directory_path,
                        )?;
                    }
                    ReceivedMessage::CopyItem(ref plist) => {
                        mb2_handle_copy_item_message(
                            &mobilebackup2_client,
                            plist,
                            &backup_root_directory_path,
                        )?;
                    }
                    ReceivedMessage::ProcessMessage(ref plist) => {
                        mb2_handle_process_message(&mobilebackup2_client, plist)?;

                        // need to quit cleanly
                        return Ok(());
                    }
                    ReceivedMessage::PurgeDiskSpace => {
                        mb2_handle_purge_disk_space_message(&mobilebackup2_client)?;
                    }
                    ReceivedMessage::Disconnect => return Ok(()),
                    // TODO: add missing arms
                    _ => (),
                }
            }
            Err(Mobilebackup2Error(err)) => match err {
                ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_RECEIVE_TIMEOUT => {
                    println!("Receive time out, retry ...");
                }
                _ => {
                    println!("Receive message error: {:?}", err);
                    return Err(From::from(Mobilebackup2Error(err)));
                }
            },
        }
    }
}

fn write_restore_applications(info_plist: &Plist, afc_client: &AfcClient) -> Result<()> {
    match info_plist.dict_get_item("Applications") {
        Some(applications_plist) => {
            let applications_xml = applications_plist
                .to_xml()
                .ok_or(anyhow!("failed to convert plist into xml"))?;

            afc_client.make_directory(ITUNES_RESTORE_DIR)?;
            let file = afc_client.file_open(
                ITUNES_RESTORE_RESTORE_APPLICATION_PLIST_FILE,
                ffi::afc_file_mode_t::AFC_FOPEN_WR,
            )?;
            let written = file.write(applications_xml.as_slice())?;
            if written as usize != applications_xml.len() {
                return Err(anyhow!(
                    "failed to write {} {} of {} bytes",
                    ITUNES_RESTORE_RESTORE_APPLICATION_PLIST_FILE,
                    written,
                    applications_xml.len()
                ));
            }
        }
        None => eprintln!("failed to get 'Applications' entry, skipping"),
    }

    Ok(())
}

fn mb2_finishing_handling_message(client: &Mobilebackup2Client, result: Result<()>) -> Result<()> {
    match result {
        Ok(_) => {
            let empty = Plist::new_dict();
            client.send_status_response(0, None, empty)?;

            Ok(())
        }
        Err(error) => {
            println!("finishing handling message: {:?}", error);
            match error.downcast_ref::<io::Error>() {
                Some(io_error) => {
                    if let Some(errno) = io_error.raw_os_error() {
                        let msg = io_error.description();

                        client.send_os_status_response(errno, Some(msg))?;
                    } else {
                        client.send_os_status_response(22, None)?;
                    }
                }
                None => {
                    client.send_os_status_response(22, None)?;
                }
            }

            Err(From::from(error))
        }
    }
}

fn mb2_handle_receive_files_message(
    client: &Mobilebackup2Client,
    message: &Plist,
    backup_path: &Path,
) -> Result<()> {
    let plist = message;

    let backup_total_size = plist.array_get_item(3).ok_or(anyhow!(format!(
        "total backup size in plist is not valud({} @ {}",
        std::file!(),
        std::line!()
    )))?;

    let backup_total_size = backup_total_size.uint_value().ok_or(anyhow!(format!(
        "failed to get total backup size ({} @ {}",
        std::file!(),
        std::line!()
    )))?;

    if backup_total_size > 0 {
        println!("Receiving files ...\n");
    }

    let result = mb2_receive_files(client, backup_path);

    mb2_finishing_handling_message(client, result)?;

    Ok(())
}

fn mb2_receive_files(client: &Mobilebackup2Client, backup_path: &Path) -> Result<()> {
    // during test, it seems to be 256 * 1024 at most
    const BUF_LEN: usize = 1024 * 1024; //32768;
    let mut receiving_buffer = Vec::<u8>::new();
    receiving_buffer.resize(BUF_LEN, 0);

    let mut last_code = 0 as u8;
    loop {
        let _dname = match mb2_receive_filename(client) {
            Ok(filename) => filename,
            Err(other) => {
                match other.downcast_ref::<Mobilebackup2Error>() {
                    Some(err) => {
                        let Mobilebackup2Error(errcode) = err;
                        match errcode {
                            ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_SUCCESS => {
                                break;
                            }
                            _ => (),
                        }
                    }
                    _ => (),
                }

                return Err(From::from(other));
            }
        };

        let local_name = mb2_receive_filename(client)?;

        // println!("dname: {}", dname);
        println!("local_name: {}", local_name);

        let local_path = backup_path.join(local_name);

        let mut file_length = client.receive_raw_u32()?;
        let mut code: u8;
        if file_length > 0 {
            code = client.receive_raw_u8()?;
        } else {
            break;
        }

        if code != CODE_SUCCESS && code != CODE_FILE_DATA && code != CODE_ERROR_REMOTE {
            println!("Found new flag: {:#x}", code);
        }

        let result = fs::remove_file(&local_path);
        // Only I ignore not found error
        if let Err(error) = result {
            if io::ErrorKind::NotFound != error.kind() {
                return Err(From::from(error));
            }
        }

        let mut file = File::create(&local_path)?;

        while file_length > 0 && code == CODE_FILE_DATA {
            // minus code size (one byte)
            let block_length = file_length - 1;
            let _received_len = mb2_receive_block(
                client,
                &mut receiving_buffer,
                block_length,
                |buffer: &[u8]| {
                    file.write(&buffer[..])?;

                    Ok(())
                },
            )?;

            file_length = client.receive_raw_u32()?;
            if file_length > 0 {
                last_code = code;
                code = client.receive_raw_u8()?;

                if code != CODE_SUCCESS && code != CODE_FILE_DATA && code != CODE_ERROR_REMOTE {
                    println!("Found new flag: {:#x}", code);
                    break;
                }
            } else {
                break;
            }
        }

        if file_length == 0 {
            break;
        }

        // If sent using CODE_FILE_DATA, end marker will be CODE_ERROR_REMOTE which is not an error!
        if code == CODE_ERROR_REMOTE {
            let length = file_length - 1;
            let mut message = String::with_capacity(length as usize);
            mb2_receive_block(client, &mut receiving_buffer, length, |buffer: &[u8]| {
                let msg = String::from_utf8_lossy(buffer);
                if let Cow::Borrowed(msg) = msg {
                    message.push_str(msg);
                } else if let Cow::Owned(msg) = msg {
                    message.push_str(&msg);
                }
                Ok(())
            })?;

            if last_code != CODE_FILE_DATA {
                println!("Received an error message from device: {}", &message);
            }
        }
    }

    Ok(())
}

fn mb2_receive_block<F>(
    client: &Mobilebackup2Client,
    buffer: &mut dyn AsMut<Vec<u8>>,
    total_length: u32,
    mut func: F,
) -> Mobilebackup2Result<u32>
where
    F: FnMut(&[u8]) -> io::Result<()>,
{
    let mut buffer = buffer.as_mut();
    // receiving one block of CODE_FILE_DATA
    let mut received_block_length = 0 as u32;
    while received_block_length < total_length {
        let left_length = total_length - received_block_length;
        let buf_len = buffer.len();
        let receiving_len = if left_length > buf_len as u32 {
            buf_len as u32
        } else {
            left_length
        };

        let received_len = client.receive_raw(&mut buffer, receiving_len)?;
        let _ = func(&buffer[..(received_len as usize)]);
        if received_len == 0 {
            break;
        }
        received_block_length += receiving_len;
    }

    Ok(received_block_length)
}

fn mb2_receive_filename(client: &Mobilebackup2Client) -> Result<String> {
    let length = mb2_receive_filename_length(client)?;
    let full_length = length + 1;
    let mut data = Vec::<u8>::with_capacity(full_length as usize);
    data.resize(full_length as usize, 0);
    let _read_length = client.receive_raw(&mut data, length)?;
    let filename = CStr::from_bytes_with_nul(&data)?;
    let filename = filename.to_string_lossy().into_owned();

    Ok(filename)
}

fn mb2_receive_filename_length(client: &Mobilebackup2Client) -> Result<u32> {
    loop {
        let result = client.receive_raw_u32();
        match result {
            Ok(length) => {
                if length > 0 {
                    return Ok(length);
                } else {
                    // if length is 0, just return / break loop
                    return Err(From::from(Mobilebackup2Error(
                        ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_SUCCESS,
                    )));
                }
            }
            Err(Mobilebackup2Error(err)) => match err {
                ffi::mobilebackup2_error_t::MOBILEBACKUP2_E_RECEIVE_TIMEOUT => {
                    continue;
                }
                _ => {
                    return Err(From::from(Mobilebackup2Error(err)));
                }
            },
        }
    }
}

fn mb2_handle_send_files(
    client: &Mobilebackup2Client,
    message: &Plist,
    backup_path: &Path,
) -> Result<()> {
    let plist = message;
    let files = plist.array_get_item(1).ok_or(anyhow!(format!(
        "failed to get files({} @ {}",
        std::file!(),
        std::line!()
    )))?;
    let count = files.array_get_size();
    let mut errors = Vec::<(PathBuf, Plist)>::new();
    for i in 0..count {
        let file = files.array_get_item(i).ok_or(anyhow!(format!(
            "failed to get file @ {}({} @ {}",
            i,
            std::file!(),
            std::line!()
        )))?;
        // as noted in implementation in libimobiledevice/tools/idevicebackup2.c,
        // here may just ignore error status and continue
        let file = file.string_value().ok_or(anyhow!(format!(
            "failed to get file name @ {}({} @ {}",
            i,
            std::file!(),
            std::line!()
        )))?;

        let file = PathBuf::from(file);
        let ret = mb2_handle_send_file(client, backup_path, &file, &mut errors);
        if let Err(_err) = ret {
            let path = backup_path.join(&file);
            println!("failed to send file at {:?}", path);
        }
    }

    println!("send terminating 0 dword");
    // send terminating 0 dword
    client.send_raw_u32(0)?;

    let mut errplist = Plist::new_dict().unwrap();

    if errors.len() > 0 {
        for (path, plist) in errors {
            let path = path.to_str().ok_or(anyhow!(format!(
                "failed to convert path({:?}) to string({} @ {}",
                path,
                std::file!(),
                std::line!()
            )))?;
            errplist.dict_set_item(path, plist);
        }
        println!("send_status_response: {:?}", errplist);
        client.send_status_response(-13, Some("Multi status"), Some(errplist))?;
    } else {
        println!("send_status_response(0, null, empty)");
        client.send_status_response(0, None, Some(errplist))?;
    }
    Ok(())
}

fn mb2_handle_send_file(
    client: &Mobilebackup2Client,
    backup_path: &Path,
    path: &Path,
    errors: &mut Vec<(PathBuf, Plist)>,
) -> Result<()> {
    let local_full_path = backup_path.join(path);
    let remote_path_str = path.to_str().ok_or(anyhow!(format!(
        "failed to convert path({:?}) to string({} @ {}",
        local_full_path,
        std::file!(),
        std::line!()
    )))?;

    let remote_path_cstr = CString::new(remote_path_str).map_err(|_| {
        anyhow!(format!(
            "failed to convert string({}) to cstring({} @ {}",
            remote_path_str,
            std::file!(),
            std::line!()
        ))
    })?;

    println!("remote_path_cstr: {:?}", remote_path_cstr);
    let data = remote_path_cstr.as_bytes();

    // send path length and path
    client.send_raw_u32(data.len() as u32)?;
    client.send_raw(data)?;

    if local_full_path.exists() {
        let file_metadata = fs::metadata(&local_full_path)?;
        let file_total_size = file_metadata.len() as usize;
        println!("sending '{}' ({} bytes)", remote_path_str, file_total_size);

        let mut f = File::open(&local_full_path)?;

        const BUF_LEN: usize = 32768;
        let mut buf = [0 as u8; BUF_LEN];

        let mut sent: usize = 0;
        while sent < file_total_size {
            let diff = file_total_size - sent;
            let length = if diff >= BUF_LEN { BUF_LEN } else { diff };
            let mut real_buf = &mut buf[0..length];
            f.read_exact(&mut real_buf)?;
            mb2_send_block_header(client, length as u32, CODE_FILE_DATA)?;
            client.send_raw(&real_buf)?;
            sent += length as usize;
        }

        mb2_send_block_header(client, 0, CODE_SUCCESS)?;
        println!("sending done");

        Ok(())
    } else {
        let error_desc = "No such file or directory";
        let error_desc_cstr = CString::new(error_desc).unwrap();
        let data = error_desc_cstr.as_bytes();
        let length = data.len();
        println!("Sending block({}: {})", std::file!(), std::line!());
        mb2_send_block_header(client, length as u32, CODE_ERROR_LOCAL)?;
        client.send_raw(&data)?;

        let plist = mb2_multi_status_add_file_error(&path, -6, error_desc);
        errors.push((path.to_path_buf(), plist));

        Err(From::from(io::Error::new(
            io::ErrorKind::NotFound,
            anyhow!(format!(
                "path({:?}) is not found({} @ {}",
                local_full_path,
                std::file!(),
                std::line!()
            )),
        )))
    }
}

#[inline]
fn mb2_send_block_header(client: &Mobilebackup2Client, length: u32, code: u8) -> Result<()> {
    let mut header = [0 as u8; 5];
    let length = length + 1;
    let bytes = length.to_be_bytes();
    header[0..4].copy_from_slice(&bytes);
    header[4] = code;
    client.send_raw(&header)?;

    Ok(())
}

fn mb2_multi_status_add_file_error(_path: &Path, error_code: i64, error_message: &str) -> Plist {
    let mut filedict = Plist::new_dict().unwrap();
    if let Some(error_message) = Plist::new_string(error_message) {
        filedict.dict_set_item("DLFileErrorString", error_message);
    }

    if let Some(error_code) = Plist::new_int(error_code) {
        filedict.dict_set_item("DLFileErrorCode", error_code);
    }

    filedict
}

fn mb2_handle_process_message(_client: &Mobilebackup2Client, message: &Plist) -> Result<()> {
    println!("process message");
    if let Some(root) = message.array_get_item(1) {
        if let Plist::Dict(_) = &root {
            if let Some(error_code) = root.dict_get_item("ErrorCode") {
                if let Some(error_code) = error_code.uint_value() {
                    println!("error_code: {}", error_code);
                    if error_code == 0 {
                    } else {
                    }
                }
                if let Some(error_desc) = root.dict_get_item("ErrorDescription") {
                    if let Some(error_desc) = error_desc.string_value() {
                        println!("error_desc: {}", error_desc);
                    }
                }
                if let Some(content) = root.dict_get_item("Content") {
                    if let Some(content) = content.string_value() {
                        println!("content: {}", content);
                    }
                }
            }
        }
    }

    Ok(())
}

fn mb2_handle_get_free_space(client: &Mobilebackup2Client, backup_path: &Path) -> Result<()> {
    let path_cstr = CString::new(backup_path.as_os_str().as_bytes())?;
    unsafe {
        let mut stat: libc::statvfs = mem::zeroed();
        let err = libc::statvfs(path_cstr.as_ptr(), &mut stat);
        if err == 0 {
            let freespace = stat.f_frsize * (stat.f_bavail as u64);
            let plist = Plist::new_uint(freespace).expect(
                format!(
                    "failed to create Plist::uint({} @ {}",
                    std::file!(),
                    std::line!()
                )
                .as_str(),
            );
            client.send_status_response(err, None, Some(plist))?;

            Ok(())
        } else {
            Err(From::from(io::Error::last_os_error()))
        }
    }
}

fn mb2_handle_purge_disk_space_message(client: &Mobilebackup2Client) -> Result<()> {
    let empty = Plist::new_dict().ok_or(anyhow!("failed to create emtpy plist dict"))?;
    client.send_status_response(-1, Some("Operation not supported"), Some(empty))?;

    Ok(())
}

fn mb2_handle_contents_of_directory_message(
    client: &Mobilebackup2Client,
    plist: &Plist,
    backup_path: &Path,
) -> Result<()> {
    let entry = plist.array_get_item(1).ok_or(anyhow!(format!(
        "failed to get directory entry plist({} @ {}",
        std::file!(),
        std::line!()
    )))?;
    let entry = entry.string_value().ok_or(anyhow!(format!(
        "failed to get directory entry string value({} @ {}",
        std::file!(),
        std::line!()
    )))?;
    let target_path = backup_path.join(entry);
    let mut contents = Plist::new_dict().ok_or(anyhow!(format!(
        "failed to create new dict({} @ {}",
        std::file!(),
        std::line!()
    )))?;

    let entries = fs::read_dir(target_path)?;
    for entry in entries {
        if let Ok(entry) = entry {
            if let Ok(metadata) = entry.metadata() {
                if let Some(mut filedict) = Plist::new_dict() {
                    const DL_FILE_TYPE_UNKNOWN: &'static str = "DLFileTypeUnknown";
                    const DL_FILE_TYPE_REGULAR: &'static str = "DLFileTypeRegular";
                    const DL_FILE_TYPE_DIRECTORY: &'static str = "DLFileTypeDirectory";

                    let filename_osstr = entry.file_name();
                    let filename = filename_osstr.to_str().ok_or(anyhow!(format!(
                        "failed to retreive filename({} @ {}",
                        std::file!(),
                        std::line!()
                    )))?;
                    let file_type: &str;
                    if metadata.is_dir() {
                        file_type = DL_FILE_TYPE_DIRECTORY;
                    } else if metadata.is_file() {
                        file_type = DL_FILE_TYPE_REGULAR;
                    } else {
                        file_type = DL_FILE_TYPE_UNKNOWN;
                    }
                    let file_type = Plist::new_string(file_type).ok_or(anyhow!(format!(
                        "failed to create plist string filename({} @ {}",
                        std::file!(),
                        std::line!()
                    )))?;
                    filedict.dict_set_item("DLFileType", file_type);

                    let file_size = metadata.len();
                    let file_size = Plist::new_uint(file_size).ok_or(anyhow!(format!(
                        "failed to create plist uint file size({} @ {}",
                        std::file!(),
                        std::line!()
                    )))?;
                    filedict.dict_set_item("DLFileSize", file_size);

                    if let Ok(modified) = metadata.modified() {
                        let modified =
                            Plist::new_date_from_systime(modified).ok_or(anyhow!(format!(
                                "failed to create plist date({} @ {}",
                                std::file!(),
                                std::line!()
                            )))?;
                        filedict.dict_set_item("DLFileModificationDate", modified);
                    }

                    contents.dict_set_item(filename, filedict);
                }
            }
        }
    }

    client.send_status_response(0, None, Some(contents))?;

    Ok(())
}

fn mb2_handle_create_directory_message(
    client: &Mobilebackup2Client,
    plist: &Plist,
    backup_path: &Path,
) -> Result<()> {
    let dir = plist.array_get_item(1).ok_or(anyhow!(format!(
        "failed to get directory entry plist({} @ {}",
        std::file!(),
        std::line!()
    )))?;
    let dir = dir.string_value().ok_or(anyhow!(format!(
        "failed to get directory entry string value({} @ {}",
        std::file!(),
        std::line!()
    )))?;
    let target_path = backup_path.join(dir);

    let result = fs::DirBuilder::new().recursive(true).create(target_path);

    if result.is_ok() {
        client.send_status_response(0, None, None)?;

        Ok(())
    } else {
        let oserror = client.send_last_os_status_response()?;

        Err(From::from(oserror))
    }
}

fn mb2_handle_move_files_message(
    client: &Mobilebackup2Client,
    plist: &Plist,
    backup_path: &Path,
) -> Result<()> {
    let files = plist.array_get_item(1).ok_or(anyhow!(format!(
        "failed to get moves files({} @ {}",
        std::file!(),
        std::line!()
    )))?;
    let _size = files.dict_get_size();
    let files_iter = files.dict_iter();
    let iter = files_iter.ok_or(anyhow!(format!(
        "failed to get files iterator({} @ {}",
        std::file!(),
        std::line!()
    )))?;
    if let Err(_error) = mb2_move_files(iter, backup_path) {
        client.send_last_os_status_response()?;
        Ok(())
    } else {
        let empty = Plist::new_dict();
        client.send_status_response(0, None, empty)?;
        Ok(())
    }
}

fn mb2_move_files(iter: IterDict, backup_path: &Path) -> io::Result<()> {
    for (oldpath, value) in iter {
        if let Some(newpath) = value.string_value() {
            let newpath = backup_path.join(newpath);
            let oldpath = backup_path.join(oldpath);
            if let Ok(metadata) = fs::metadata(&newpath) {
                if metadata.is_dir() {
                    fs::remove_dir_all(&newpath)?;
                } else {
                    fs::remove_file(&newpath)?;
                }
            }
            fs::rename(oldpath, &newpath)?;
        }
    }

    Ok(())
}

fn mb2_handle_remove_item_message(
    client: &Mobilebackup2Client,
    plist: &Plist,
    backup_path: &Path,
) -> Result<()> {
    let result = mb2_handle_remove_item(client, plist, backup_path);
    mb2_finishing_handling_message(client, result)?;

    Ok(())
}

fn mb2_handle_remove_item(
    _client: &Mobilebackup2Client,
    plist: &Plist,
    backup_path: &Path,
) -> Result<()> {
    let files = plist.array_get_item(1).ok_or(anyhow!(format!(
        "failed to get removing files({} @ {}",
        std::file!(),
        std::line!()
    )))?;
    let size = files.array_get_size();
    for i in 0..size {
        if let Some(item) = files.array_get_item(i) {
            if let Some(filename) = item.string_value() {
                let filepath = backup_path.join(&filename);
                mb2_remove_item(&filepath)?;
            }
        }
    }

    Ok(())
}

fn mb2_remove_item(target_path: &Path) -> Result<()> {
    if let Ok(metadata) = fs::metadata(target_path) {
        if metadata.is_dir() {
            fs::remove_dir_all(target_path)?;
        } else if metadata.is_file() {
            fs::remove_file(target_path)?;
        }
    }

    Ok(())
}

fn mb2_handle_copy_item_message(
    client: &Mobilebackup2Client,
    plist: &Plist,
    backup_path: &Path,
) -> Result<()> {
    let result = mb2_handle_copy_item(client, plist, backup_path);
    mb2_finishing_handling_message(client, result)?;

    Ok(())
}

fn mb2_handle_copy_item(
    client: &Mobilebackup2Client,
    plist: &Plist,
    backup_path: &Path,
) -> Result<()> {
    let srcpath = plist.array_get_item(1).ok_or(anyhow!(format!(
        "failed to get copy src file({} @ {}",
        std::file!(),
        std::line!()
    )))?;
    let dstpath = plist.array_get_item(2).ok_or(anyhow!(format!(
        "failed to get copy dest file({} @ {}",
        std::file!(),
        std::line!()
    )))?;

    let srcpath = srcpath.string_value().ok_or(anyhow!(format!(
        "failed to get src file name string value({} @ {}",
        std::file!(),
        std::line!()
    )))?;
    let dstpath = dstpath.string_value().ok_or(anyhow!(format!(
        "failed to get dest file name string value ({} @ {}",
        std::file!(),
        std::line!()
    )))?;

    let srcpath = backup_path.join(&srcpath);
    let dstpath = backup_path.join(&dstpath);

    let src_meta = fs::metadata(&srcpath)?;
    if src_meta.is_dir() {
        mb2_copy_dir(&srcpath, &dstpath)?;
    } else if src_meta.is_file() {
        mb2_copy_file(&srcpath, &dstpath)?;
    }

    let empty = Plist::new_dict();
    client.send_status_response(0, None, empty)?;

    Ok(())
}

fn mb2_copy_dir(srcpath: &Path, dstpath: &Path) -> Result<()> {
    let entries = fs::read_dir(srcpath)?;
    if !dstpath.exists() {
        fs::create_dir(dstpath)?;
    }
    for entry in entries {
        if let Ok(entry) = entry {
            let filename = entry.file_name();
            if let Ok(metadata) = entry.metadata() {
                let srcpath = srcpath.join(&filename);
                let dstpath = dstpath.join(&filename);
                if metadata.is_file() {
                    mb2_copy_file(&srcpath, &dstpath)?;
                } else if metadata.is_dir() {
                    mb2_copy_dir(&srcpath, &dstpath)?;
                }
            }
        }
    }

    Ok(())
}

#[inline]
fn mb2_copy_file(srcpath: &Path, dstpath: &Path) -> Result<()> {
    fs::copy(srcpath, dstpath)?;

    Ok(())
}

fn mobilebackup_factory_info_plist_new(
    _udid: &str,
    device: Rc<Device>,
    _afc: &AfcClient,
) -> Result<Plist> {
    let lockdownd_client = LockdowndClient::new_with_handshake(device.clone(), crate_name!())?;

    let mut out_plist = Plist::new_dict().ok_or(anyhow!("new_dict returned None"))?;
    let root_node = lockdownd_client
        .get_value(None, None)?
        .ok_or(anyhow!(format!(
            "failed to get root node({} @ {}",
            std::file!(),
            std::line!()
        )))?;
    let _itunes_settings = lockdownd_client.get_value(Some("com.apple.iTunes"), None)?;
    let _min_itunes_version =
        lockdownd_client.get_value(Some("com.apple.mobile.iTunes"), Some("MinITunesVersion"))?;

    let instproxy_client = InstproxyClient::start_service(device.clone(), crate_name!())?;
    let mut options =
        ClientOptions::new().ok_or(anyhow!("failed to create instproxy client new options"))?;

    let mut key_values = HashMap::with_capacity(1);
    key_values.insert(
        "ApplicationType".to_string(),
        OptionsType::String("User".to_string()),
    );
    options.add(key_values);

    let attributes = vec![
        "CFBundleIdentifier".to_string(),
        "ApplicationSINF".to_string(),
        "iTunesMetadata".to_string(),
    ];
    options.set_return_attributes(attributes);

    println!("options: {:#?}", options);

    let apps = instproxy_client
        .browse(&options)?
        .ok_or(anyhow!("failed to browse apps"))?;
    // println!("apps: {:#?}", apps);

    let mut app_dict = Plist::new_dict().ok_or(anyhow!(format!(
        "failed to create new dict({} @ {}",
        std::file!(),
        std::line!()
    )))?;
    let mut installed_apps = Plist::new_array().ok_or(anyhow!(format!(
        "failed to create new array({} @ {}",
        std::file!(),
        std::line!()
    )))?;

    let size = apps.array_get_size();
    for i in 0..size {
        if let Some(entry) = apps.array_get_item(i) {
            if let Some(bundle_id_plist) = entry.dict_get_item("CFBundleIdentifier") {
                if let Some(bundle_id) = bundle_id_plist.string_value() {
                    installed_apps.array_append_item(bundle_id_plist);
                    if let Some(sinf) = entry.dict_get_item("ApplicationSINF") {
                        if let Some(meta) = entry.dict_get_item("iTunesMetadata") {
                            let mut adict = Plist::new_dict().ok_or(anyhow!(format!(
                                "failed to create new array({} @ {}",
                                std::file!(),
                                std::line!()
                            )))?;
                            adict.dict_set_item("ApplicationSINF", sinf);
                            adict.dict_set_item("iTunesMetadata", meta);
                            app_dict.dict_set_item(&bundle_id, adict);
                        }
                    }
                };
            }
        }
    }

    out_plist.dict_set_item("Installed Applications", installed_apps);

    out_plist.dict_set_item("Applications", app_dict);
    let out_value = root_node
        .dict_get_item("BuildVersion")
        .ok_or(anyhow!(format!(
            "failed to get BuildVersion({} @ {}",
            std::file!(),
            std::line!()
        )))?;
    out_plist.dict_set_item("Build Version", out_value);

    let out_value = root_node
        .dict_get_item("DeviceName")
        .ok_or(anyhow!(format!(
            "failed to get DeviceName({} @ {}",
            std::file!(),
            std::line!()
        )))?;
    out_plist.dict_set_item("Device Name", out_value.clone());
    out_plist.dict_set_item("Display Name", out_value);

    if let Some(out_value) = root_node.dict_get_item("IntegratedCircuitCardIdentity") {
        match out_value {
            Plist::None => (),
            other => out_plist.dict_set_item("ICCID", other),
        }
    }

    if let Some(out_value) = root_node.dict_get_item("InternationalMobileEquipmentIdentity") {
        match out_value {
            Plist::None => (),
            other => out_plist.dict_set_item("IMEI", other),
        }
    }

    let guid = Uuid::new_v4().simple().to_string();
    let guid = Plist::new_string(guid.as_str()).ok_or(anyhow!(format!(
        "failed to create GUID string({} @ {}",
        std::file!(),
        std::line!()
    )))?;
    out_plist.dict_set_item("GUID", guid);

    let now = Utc::now();
    let backup_date = Plist::new_date(now).ok_or(anyhow!(format!(
        "failed to create backup date({} @ {}",
        std::file!(),
        std::line!()
    )))?;
    out_plist.dict_set_item("Last Backup Date", backup_date);

    if let Some(out_value) = root_node.dict_get_item("MobileEquipmentIdentifier") {
        match out_value {
            Plist::None => (),
            other => out_plist.dict_set_item("MEID", other),
        }
    }

    if let Some(out_value) = root_node.dict_get_item("PhoneNumber") {
        match out_value {
            Plist::None => (),
            other => out_plist.dict_set_item("Phone Number", other),
        }
    }

    let out_value = root_node
        .dict_get_item("ProductType")
        .ok_or(anyhow!(format!(
            "failed to get ProductType({} @ {}",
            std::file!(),
            std::line!()
        )))?;
    out_plist.dict_set_item("Product Type", out_value);

    let out_value = root_node
        .dict_get_item("ProductVersion")
        .ok_or(anyhow!(format!(
            "failed to get ProductVersion({} @ {}",
            std::file!(),
            std::line!()
        )))?;
    out_plist.dict_set_item("Product Version", out_value);

    let out_value = root_node
        .dict_get_item("SerialNumber")
        .ok_or(anyhow!(format!(
            "failed to get SerialNumber({} @ {}",
            std::file!(),
            std::line!()
        )))?;
    out_plist.dict_set_item("Serial Number", out_value);

    let out_value = root_node
        .dict_get_item("UniqueDeviceID")
        .ok_or(anyhow!(format!(
            "failed to get UniqueDeviceID({} @ {}",
            std::file!(),
            std::line!()
        )))?;
    out_plist.dict_set_item("Target Identifier", out_value);

    let out_value = Plist::new_string("Device").ok_or(anyhow!(format!(
        "failed to create \"Devive\" string ({} @ {}",
        std::file!(),
        std::line!()
    )))?;
    out_plist.dict_set_item("Target Type", out_value);

    let udid_str = device.get_udid()?;
    let udid_uppercase = udid_str.to_ascii_uppercase();
    let out_value = Plist::new_string(udid_uppercase.as_str()).ok_or(anyhow!(format!(
        "failed to create \"Udid\" string ({} @ {}",
        std::file!(),
        std::line!()
    )))?;
    out_plist.dict_set_item("Unique Identifier", out_value);

    Ok(out_plist)
}

// fn mobilebackup_afc_get_file_contents(_afc: &AfcClient, _filename: &str) {
// }

fn do_post_notification(client: Rc<NpClient>, notification: &[u8]) -> Result<()> {
    client.post_notification(notification)?;

    Ok(())
}
