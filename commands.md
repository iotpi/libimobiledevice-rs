cargo run --example ideviceinfo -- -u 00008020-000804EE3C30003A -q com.apple.mobile.wireless_lockdown -k EnableWifiConnections -b true
cargo run --example idevicebackup2 -- restore --system --settings --source `source udid` `backup root path`
