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

use std::thread;
use std::time;

use anyhow::{anyhow, Result};
use libimobiledevice::idevice::DeviceEventSubscriber;

fn main() -> Result<()> {
    let subscriber = DeviceEventSubscriber::new(|event| {
        println!("device event: {:?}", event);
    });

    loop {
        println!("loop ...");
        thread::sleep(time::Duration::from_secs(2));
    }
}
