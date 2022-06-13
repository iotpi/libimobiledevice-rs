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

use clap::{crate_authors, crate_name, crate_version, App, Arg, ArgGroup};
use std::rc::Rc;

use libimobiledevice::idevice::Device;
use libimobiledevice::lockdownd::LockdowndClient;

use libimobiledevice::ffi::idevice_options;
use libplist::plist::Plist;

const KNOWN_DOMAINS: &'static [&'static str] = &[
    // copied from libimobiledevice/tools/ideviceinfo.c
    "com.apple.disk_usage",
    "com.apple.disk_usage.factory",
    "com.apple.mobile.battery",
    /* FIXME: For some reason lockdownd segfaults on this, works sometimes though
    "com.apple.mobile.debug",. */
    "com.apple.iqagent",
    "com.apple.purplebuddy",
    "com.apple.PurpleBuddy",
    "com.apple.mobile.chaperone",
    "com.apple.mobile.third_party_termination",
    "com.apple.mobile.lockdownd",
    "com.apple.mobile.lockdown_cache",
    "com.apple.xcode.developerdomain",
    "com.apple.international",
    "com.apple.mobile.data_sync",
    "com.apple.mobile.tethered_sync",
    "com.apple.mobile.mobile_application_usage",
    "com.apple.mobile.backup",
    "com.apple.mobile.nikita",
    "com.apple.mobile.restriction",
    "com.apple.mobile.user_preferences",
    "com.apple.mobile.sync_data_class",
    "com.apple.mobile.software_behavior",
    "com.apple.mobile.iTunes.SQLMusicLibraryPostProcessCommands",
    "com.apple.mobile.iTunes.accessories",
    "com.apple.mobile.internal",          /* < iOS 4.0+ */
    "com.apple.mobile.wireless_lockdown", /* < iOS 4.0+ */
    "com.apple.fairplay",
    "com.apple.iTunes",
    "com.apple.mobile.iTunes.store",
    "com.apple.mobile.iTunes",
];

fn main() {
    let mut known_domains = String::from("Known domains are:\n");
    known_domains.push_str(KNOWN_DOMAINS.join(",\n").as_str());

    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about("ideviceinfo clone from libidevicemobile")
        .after_help(known_domains.as_str())
        .arg(
            Arg::with_name("udid")
                .short("u")
                .value_name("udid")
                .help("target specific device by UDID")
                .takes_value(true),
        )
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
            Arg::with_name("string value")
                .short("s")
                .value_name("string")
                .help("set string value to key")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("boolean value")
                .short("b")
                .value_name("bool")
                .help("set bool (true | false) value to key")
                .takes_value(true),
        )
        .group(ArgGroup::with_name("value").args(&["string value", "boolean value"]))
        .get_matches();

    let udid = matches.value_of("udid");
    let domain = matches.value_of("domain");
    let key = matches.value_of("key");

    let dev = Device::new_with_options(
        udid,
        idevice_options::IDEVICE_LOOKUP_USBMUX | idevice_options::IDEVICE_LOOKUP_NETWORK,
    );
    match dev {
        Ok(device) => {
            let client = LockdowndClient::new_with_handshake(Rc::new(device), crate_name!());
            match client {
                Ok(client) => {
                    if matches.is_present("value") {
                        let value: Plist;
                        let val_str: &str;
                        if let Some(str_val_str) = matches.value_of("string value") {
                            value = Plist::new_string(str_val_str).unwrap();
                            val_str = str_val_str;
                        } else if let Some(bool_val_str) = matches.value_of("boolean value") {
                            let bool_val: bool = bool_val_str.parse().unwrap();
                            value = Plist::new_bool(bool_val).unwrap();
                            val_str = bool_val_str;
                        } else {
                            unimplemented!("not implemented value type");
                            val_str = "not implemented";
                        }
                        match client.set_value(domain, key, value) {
                            Ok(()) => (),
                            Err(err) => {
                                eprintln!(
                                    "failed to set domain {:?} key {:?} with value {:?}",
                                    domain, key, val_str
                                );
                            }
                        }
                    } else {
                        let plist = client.get_value(domain, key);
                        match plist {
                            Ok(plist) => {
                                println!("plist:{:?}", plist);
                            }
                            Err(err) => println!("Err Plist({:?})", err),
                        }
                    }
                }
                Err(err) => {
                    println!("Err Client({:?})", err)
                }
            }
        }
        Err(err) => println!("Err({:?})", err),
    }
    // match idevice::get_device_list_extended() {
    //     Ok(result) => {
    //         for d in result {
    //             println!("device udid: {}", d.udid);
    //         }
    //     }
    //     Err(err) => println!("Error: {:?}", err)
    // }
}
