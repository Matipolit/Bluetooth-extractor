use tokio::fs::File;

use bytes::BytesMut;
use pty_process::{Command, Pty};
use tokio::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone)]
struct BtAdapter {
    name: String,
    devices: Vec<BtDevice>,
}

#[derive(Debug, Clone)]
enum BtDevice {
    NonBt51 {
        address: String,
        key: String,
    },
    Bt51 {
        address: String,
        long_term_key: LongTermKey,
        identity_resolving_key: Option<String>,
        local_signature_key: Option<String>,
    },
}

impl BtDevice {
    fn has_slave_and_peripheral_keys(&self) -> bool {
        match self {
            Self::NonBt51 { address, key } => false,
            Self::Bt51 {
                address,
                long_term_key,
                identity_resolving_key,
                local_signature_key,
            } => {
                if long_term_key.rand == "0" && long_term_key.ediv == "0" {
                    true
                } else {
                    false
                }
            }
        }
    }
    fn get_long_term_key(&self) -> &LongTermKey {
        match self {
            BtDevice::Bt51 { long_term_key, .. } => long_term_key,
            _ => panic!("Called get_long_term_key on NonBt51"),
        }
    }

    fn get_identity_resolving_key(&self) -> Option<&String> {
        match self {
            BtDevice::Bt51 {
                identity_resolving_key,
                ..
            } => identity_resolving_key.as_ref(),
            _ => panic!("Called get_identity_resolving_key on NonBt51"),
        }
    }

    fn get_local_signature_key(&self) -> Option<&String> {
        match self {
            BtDevice::Bt51 {
                local_signature_key,
                ..
            } => local_signature_key.as_ref(),
            _ => panic!("Called get_local_signature_key on NonBt51"),
        }
    }
}

#[derive(Debug, Clone)]
struct LongTermKey {
    key: String,
    rand: String,
    ediv: String,
    encsize: Option<String>,
}

async fn read_until_no_increment(buf: &mut BytesMut, pty: &mut Pty) {
    let mut prev_len = buf.len();
    loop {
        match timeout(Duration::from_millis(50), pty.read_buf(buf)).await {
            Ok(Ok(_)) => {
                let new_len = buf.len();
                if new_len == prev_len {
                    break;
                }
                prev_len = new_len;
            }
            Ok(Err(e)) => {
                eprintln!("Error reading from pty: {}", e);
                break;
            }
            Err(_) => {
                // Timeout occurred
                break;
            }
        }
    }
}

async fn extract_key(
    address_line: &str,
    pty: &mut Pty,
    buf: &mut BytesMut,
    address_processed: bool,
    reversed: bool,
) -> Option<String> {
    let line = if !address_processed {
        address_line.split('<').collect::<Vec<&str>>()[1]
            .trim()
            .split('>')
            .collect::<Vec<&str>>()[0]
    } else {
        address_line
    };
    println!("Extracting hex from: {}", line);
    pty.write_all(format!("hex {}\n", line).as_bytes())
        .await
        .expect("Could not read the hex file");
    buf.clear();
    read_until_no_increment(buf, pty).await;
    let hex_lines = String::from_utf8_lossy(&buf);
    let hex_output = hex_lines.split("\n");

    for hex_line in hex_output {
        if hex_line.len() > 5 {
            if hex_line.contains(":00000") {
                let result = if !reversed {
                    hex_line[8..56]
                        .split_whitespace()
                        .collect::<String>()
                        .to_uppercase()
                } else {
                    hex_line[8..56].split_whitespace().rev().collect::<String>()
                };
                println!("Extracted: {}", result);
                return Some(result);
            }
        }
    }
    return None;
}

fn convert_mac_address(source: &String) -> String {
    source
        .chars()
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(":")
        .to_uppercase()
}

#[tokio::main]
async fn main() -> io::Result<()> {
    /*
    if !is_superuser() {
        panic!("This program should be run with sudo/admin priveleges!");
    }
    */

    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg("which chntpw")
        .output()
        .expect("Could not execute shell command!");

    if String::from_utf8_lossy(&output.stdout).trim() == "chntpw not found" {
        panic!("Please install chntpw");
    }

    println!("Enter the path to your mounted Windows partition:");
    let mut win_part = String::new();
    std::io::stdin()
        .read_line(&mut win_part)
        .expect("Failed to read line");
    win_part = win_part.trim().to_string();
    println!("\nUsing {} as your Windows partition", win_part);
    println!("Spawning chntpw");

    let mut binding = Command::new("chntpw");
    let mut command = binding
        .arg("-e")
        .arg("SYSTEM")
        .current_dir(format!("{}/Windows/System32/config", win_part));

    let mut pty = Pty::new().unwrap();
    let chnptw = command
        .spawn(&pty.pts().unwrap())
        .expect("Could not spawn child process");

    // Write 'ls' command to chntpw
    println!("Writing ls to chntpw");
    pty.write_all(b"ls\n")
        .await
        .expect("Failed to write ls to stdin");

    println!("Wrote ls");
    // Read output and react to it
    let mut buf = BytesMut::with_capacity(1024);
    let mut str_buf = String::with_capacity(1024);

    let mut ctrl_set_string = BytesMut::with_capacity(128);

    read_until_no_increment(&mut buf, &mut pty).await;
    str_buf = String::from_utf8_lossy(&buf).to_string();
    println!("ls output: {}", str_buf);
    if str_buf.contains("CurrentControlSet") {
        ctrl_set_string
            .extend_from_slice(b"cd CurrentControlSet\\Services\\BTHPORT\\Parameters\\Keys\n");
        println!("Saved CurrentControlSet, waiting for the output to end");
    } else if str_buf.contains("ControlSet00") {
        println!("Searching for the tag...");
        let start_tag = "<ControlSet";
        let end_tag = ">";
        let start_pos = str_buf.find(start_tag);

        if let Some(start) = start_pos {
            let end_pos = str_buf[start..].find(end_tag);
            if let Some(end) = end_pos {
                let control_set = &str_buf[start + 1..start + end];
                ctrl_set_string.extend_from_slice(b"cd ");
                ctrl_set_string.extend_from_slice(control_set.as_bytes());
                ctrl_set_string.extend_from_slice(b"\\Services\\BTHPORT\\Parameters\\Keys\n");
                println!("Saved {}", String::from_utf8_lossy(&ctrl_set_string));
            }
        }
    } else {
        panic!("Something went wrong with chntpw, could not find a ControlSet.");
    }
    buf.clear();
    str_buf.clear();
    println!("Going into bt adapters");
    pty.write_all(&ctrl_set_string)
        .await
        .expect("Failed to cd into BT adapters");

    println!("Retrieving the address of your BT adapter(s)");
    pty.write_all(b"ls\n")
        .await
        .expect("Failed to list BT adapters");

    read_until_no_increment(&mut buf, &mut pty).await;
    str_buf = String::from_utf8_lossy(&buf).to_string();

    let adapters_str: Vec<&str> = str_buf.split("key name").collect();
    //println!("adapters_str: {:?}", adapters_str);
    let adapters_str_list: std::str::Split<&str> = adapters_str[1].split("\n");
    let mut adapters: Vec<BtAdapter> = Vec::with_capacity(1);
    for mut adapter in adapters_str_list {
        if adapter.len() > 2 {
            adapter = adapter.trim();
            if adapter.contains("<") {
                adapter = adapter.trim_matches(['<', '>']);
                adapters.push(BtAdapter {
                    name: adapter.to_string(),
                    devices: Vec::with_capacity(1),
                });
            }
        }
    }
    println!("Retrieved {} adapters.", adapters.len());
    for adapter in &mut adapters {
        pty.write_all(format!("cd {}\n", adapter.name).as_bytes())
            .await
            .expect(format!("Could not cd into adapter's {} directory", adapter.name).as_str());
        read_until_no_increment(&mut buf, &mut pty).await;

        pty.write_all(b"ls\n")
            .await
            .expect(format!("Could not ls in adapter's {} directory", adapter.name).as_str());

        buf.clear();
        str_buf.clear();
        read_until_no_increment(&mut buf, &mut pty).await;
        str_buf = String::from_utf8_lossy(&buf).to_string();
        let str_buf_clone = str_buf.clone();
        let split_buf = str_buf_clone.split("\n");

        for mut potential_key in split_buf {
            if potential_key.contains("<") {
                if potential_key.contains("REG_BINARY") {
                    // potential < 5.1 key
                    if !potential_key.contains("CentralIRK") {
                        potential_key = potential_key.split('<').collect::<Vec<&str>>()[1]
                            .split('>')
                            .collect::<Vec<&str>>()[0];

                        match extract_key(potential_key, &mut pty, &mut buf, true, false).await {
                            Some(key) => adapter.devices.push(BtDevice::NonBt51 {
                                address: potential_key.to_string(),
                                key,
                            }),
                            None => (),
                        }
                    }
                } else {
                    // 5.1 key
                    println!("Potential 5.1 key: {}", potential_key);
                    potential_key = potential_key.split('<').collect::<Vec<&str>>()[1]
                        .split('>')
                        .collect::<Vec<&str>>()[0];

                    // enter the 5.1 device folder
                    pty.write_all(format!("cd {}\n", potential_key).as_bytes())
                        .await
                        .expect(
                            format!("Could not cd into BT 5.1 device: {}", potential_key).as_str(),
                        );
                    pty.write_all(b"ls\n").await.expect(
                        format!("Could not cd into BT 5.1 device: {}", potential_key).as_str(),
                    );
                    buf.clear();
                    str_buf.clear();
                    read_until_no_increment(&mut buf, &mut pty).await;

                    str_buf = String::from_utf8_lossy(&buf).to_string();
                    println!("5.1 folder: {}", str_buf);
                    let folder_lines = str_buf.split("\n");
                    let mut ltk: LongTermKey = LongTermKey {
                        key: "".to_string(),
                        rand: "".to_string(),
                        ediv: "".to_string(),
                        encsize: None,
                    };
                    let mut irk: Option<String> = None;
                    let mut sig: Option<String> = None;

                    for folder_line in folder_lines {
                        if folder_line.contains("LTK") {
                            match extract_key(folder_line, &mut pty, &mut buf, false, false).await {
                                Some(key) => ltk.key = key,
                                None => {}
                            }
                        } else if folder_line.contains("KeyLength") {
                            match extract_key(folder_line, &mut pty, &mut buf, false, true).await {
                                Some(key) => {
                                    ltk.encsize = Some(
                                        u64::from_str_radix(key.as_str(), 16).unwrap().to_string(),
                                    )
                                }
                                None => {}
                            }
                        } else if folder_line.contains("EDIV") {
                            match extract_key(folder_line, &mut pty, &mut buf, false, true).await {
                                Some(key) => {
                                    ltk.ediv =
                                        u64::from_str_radix(key.as_str(), 16).unwrap().to_string()
                                }
                                None => {}
                            }
                        } else if folder_line.contains("ERand") {
                            match extract_key(folder_line, &mut pty, &mut buf, false, true).await {
                                Some(key) => {
                                    ltk.rand =
                                        u64::from_str_radix(key.as_str(), 16).unwrap().to_string()
                                }
                                None => {}
                            }
                        } else if folder_line.contains("IRK")
                            && !folder_line.contains("CEntralIRKStatus")
                        {
                            match extract_key(folder_line, &mut pty, &mut buf, false, false).await {
                                Some(key) => irk = Some(key),
                                None => {}
                            }
                        } else if folder_line.contains("CSRK") {
                            match extract_key(folder_line, &mut pty, &mut buf, false, false).await {
                                Some(key) => sig = Some(key),
                                None => {}
                            }
                        }
                    }

                    let device = BtDevice::Bt51 {
                        address: potential_key.to_string(),
                        long_term_key: ltk,
                        identity_resolving_key: irk,
                        local_signature_key: sig,
                    };
                    adapter.devices.push(device);

                    pty.write_all(b"cd ..\n").await.expect("Could not cd up");
                }
            }
        }
    }
    // Save the extracted keys into existing device folders in the linux filesystem

    println!("\n\n");

    for adapter in &adapters {
        let adapter_path = format!("/var/lib/bluetooth/{}", convert_mac_address(&adapter.name));
        println!("Adapter path: {}", &adapter_path);
        if std::fs::metadata(&adapter_path).is_ok() {
            for bt_device in &adapter.devices {
                let address = match bt_device {
                    BtDevice::NonBt51 { address, .. } => address,
                    BtDevice::Bt51 { address, .. } => address,
                };
                let device_path =
                    format!("{}/{}/info", &adapter_path, convert_mac_address(&address));
                if std::fs::metadata(&device_path).is_ok() {
                    println!("Saving new data in file: {}", &device_path);
                    let file = File::open(device_path).await?;
                    let reader = BufReader::new(file);
                    let mut contents = String::new();

                    let mut lines = reader.lines();
                    let mut in_section = false;
                    let mut section_name = "".to_string();

                    while let Some(line) = lines.next_line().await? {
                        if line.starts_with('[') && line.ends_with(']') {
                            in_section = match bt_device {
                                BtDevice::Bt51 { .. } => {
                                    section_name = line[1..line.len() - 1].to_string();
                                    matches!(
                                        section_name.as_str(),
                                        "LongTermKey"
                                            | "IdentityResolvingKey"
                                            | "LocalSignatureKey"
                                    )
                                }
                                BtDevice::NonBt51 { .. } => {
                                    section_name = line[1..line.len() - 1].to_string();
                                    section_name == "LinkKey"
                                }
                            };
                        }

                        if in_section {
                            match section_name.as_str() {
                                "LongTermKey" => {
                                    if line.starts_with("Key=") {
                                        contents.push_str(&format!(
                                            "Key={}\n",
                                            bt_device.get_long_term_key().key
                                        ));
                                        continue;
                                    }
                                    if line.starts_with("EncSize=") {
                                        contents.push_str(&format!(
                                            "EncSize={}\n",
                                            bt_device.get_long_term_key().encsize.as_ref().unwrap()
                                        ));
                                        continue;
                                    }
                                }
                                "IdentityResolvingKey" => {
                                    if line.starts_with("Key=") {
                                        contents.push_str(&format!(
                                            "Key={}\n",
                                            bt_device.get_identity_resolving_key().unwrap()
                                        ));
                                        continue;
                                    }
                                }
                                "LocalSignatureKey" => {
                                    if line.starts_with("Key=") {
                                        contents.push_str(&format!(
                                            "Key={}\n",
                                            bt_device.get_local_signature_key().unwrap()
                                        ));
                                        continue;
                                    }
                                }
                                "LinkKey" => {
                                    if line.starts_with("Key=") {
                                        if let BtDevice::NonBt51 { key, .. } = bt_device {
                                            contents.push_str(&format!("Key={}\n", key));
                                            continue;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }

                        contents.push_str(&line);
                        contents.push('\n');
                    }
                } else {
                    println!("Device with addr. {} not found in the linux filesystem. Perhaps it was never connected on linux?", &address);
                }
            }
        } else {
            println!(
                "Adapter {} not found in the linux filesystem.",
                adapter.name
            );
        }
    }

    println!("\n Done saving keys. Now restarting the bluetooth service.");
    let output = std::process::Command::new("systemctl")
        .arg("restart")
        .arg("bluetooth")
        .output()
        .expect("Could not restart the bluetooth service!");

    println!("Output: {:?}", output);
    println!("Done!");
    println!("It's possible that a full reboot is required for the changes to take effect.");

    Ok(())
}
