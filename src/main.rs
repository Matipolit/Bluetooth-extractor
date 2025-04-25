use bytes::BytesMut;
use pty_process::{Command, Pty};
use std::path::Path;
use tokio::fs::{File, OpenOptions};
use tokio::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::{timeout, Duration};

// Define a simple error type for the application
#[derive(thiserror::Error, Debug)]
enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("PTY interaction error: {0}")]
    Pty(String),
    #[error("Command execution error: {0}")]
    Command(String),
    #[error("Parsing error: {0}")]
    Parse(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Timeout error: {0}")]
    Timeout(String),
}

// Define a result type using our custom error
type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, Clone)]
struct BtAdapter {
    name: String, // MAC address without colons
    devices: Vec<BtDevice>,
}

#[derive(Debug, Clone)]
enum BtDevice {
    NonBt51 {
        address: String, // MAC address without colons
        key: String,
    },
    Bt51 {
        address: String, // MAC address without colons
        long_term_key: LongTermKey,
        identity_resolving_key: Option<String>,
        local_signature_key: Option<String>,
    },
}

impl BtDevice {
    fn address(&self) -> &str {
        match self {
            BtDevice::NonBt51 { address, .. } => address,
            BtDevice::Bt51 { address, .. } => address,
        }
    }
    // Note: Removed panic-prone getter methods. Access fields directly
    // via pattern matching where the device is used.
}

#[derive(Debug, Clone)]
struct LongTermKey {
    key: String,
    rand: String,            // Stored as decimal string representation
    ediv: String,            // Stored as decimal string representation
    encsize: Option<String>, // Stored as decimal string representation
}

/// Reads from the PTY into the buffer until no new data arrives for a short duration.
async fn read_until_stable(
    buf: &mut BytesMut,
    pty: &mut Pty,
    read_timeout: Duration,
    stable_duration: Duration,
) -> Result<()> {
    loop {
        match timeout(read_timeout, pty.read_buf(buf)).await {
            Ok(Ok(0)) => {
                // EOF reached. This might be okay if expected, or an error otherwise.
                // Depending on context, might want to return Ok(()) or an error.
                // For now, assume it's okay if *some* data was read before EOF.
                if buf.is_empty() {
                    return Err(AppError::Pty(
                        "PTY closed unexpectedly before any data was read".to_string(),
                    ));
                } else {
                    println!("PTY closed (EOF).");
                    return Ok(());
                }
            }
            Ok(Ok(_n)) => {
                // Data read, continue to check stability
                // Reset the stability timer implicitly by looping
            }
            Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => {
                // This shouldn't typically happen with pty_process + tokio,
                // but handle defensively. Treat as timeout.
                println!("Read would block, treating as stable.");
                return Ok(());
            }
            Ok(Err(e)) => {
                eprintln!("Error reading from pty: {}", e);
                return Err(AppError::Io(e));
            }
            Err(_) => {
                // Timeout occurred - means no data read for stable_duration
                // This indicates the output has stabilized.
                return Ok(());
            }
        }

        // Optional small delay to prevent tight loop in certain edge cases,
        // though read_buf should block appropriately.
        // tokio::time::sleep(Duration::from_millis(5)).await;

        // Check stability explicitly with another timeout
        // This version relies on the outer timeout expiring when no data is read.
        // An alternative is to measure time since last successful read.
        // The current approach using a single timeout on read_buf is simpler.
    }
}

/// Waits for the chntpw prompt "> " to appear in the buffer.
async fn wait_for_prompt(
    pty: &mut Pty,
    buf: &mut BytesMut,
    overall_timeout: Duration,
) -> Result<()> {
    let prompt = b"> ";
    let start_time = tokio::time::Instant::now();

    loop {
        if start_time.elapsed() > overall_timeout {
            return Err(AppError::Timeout(format!(
                "Timeout waiting for chntpw prompt (> ). Buffer: {:?}",
                String::from_utf8_lossy(buf)
            )));
        }

        // Use a shorter timeout for each read attempt
        match timeout(Duration::from_secs(1), pty.read_buf(buf)).await {
            Ok(Ok(0)) => {
                return Err(AppError::Pty(
                    "PTY closed unexpectedly while waiting for prompt".to_string(),
                ));
            }
            Ok(Ok(_n)) => {
                // Check if the buffer *ends* with the prompt
                if buf.ends_with(prompt) {
                    println!("Prompt detected.");
                    return Ok(());
                }
                // If not, continue reading
            }
            Ok(Err(e)) => {
                eprintln!("Error reading from pty while waiting for prompt: {}", e);
                return Err(AppError::Io(e));
            }
            Err(_) => {
                // Read timed out, but overall timeout hasn't expired.
                // Continue waiting. Check buffer just in case.
                if buf.ends_with(prompt) {
                    println!("Prompt detected after read timeout.");
                    return Ok(());
                }
            }
        }
    }
}

/// Sends a command to the PTY, ensuring it ends with a newline.
async fn send_command(pty: &mut Pty, cmd: &str) -> Result<()> {
    println!("Sending command: {}", cmd);
    pty.write_all(cmd.as_bytes()).await?;
    if !cmd.ends_with('\n') {
        pty.write_all(b"\n").await?;
    }
    pty.flush().await?; // Ensure it's sent
    Ok(())
}

/// Extracts a hex value using the 'hex' command in chntpw.
async fn extract_key(
    value_name_line: &str, // The line from 'ls' containing the value name like "<LTK>"
    pty: &mut Pty,
    buf: &mut BytesMut,
    reversed: bool,
) -> Result<Option<String>> {
    // Extract the value name between < >
    let start = value_name_line.find('<');
    let end = value_name_line.find('>');
    let value_name = match (start, end) {
        (Some(s), Some(e)) if s < e => &value_name_line[s + 1..e],
        _ => {
            eprintln!(
                "Could not extract value name from line: {}",
                value_name_line
            );
            return Ok(None); // Cannot proceed without a name
        }
    };

    println!("Extracting hex for value: {}", value_name);
    buf.clear(); // Clear buffer before sending command
    send_command(pty, &format!("hex {}", value_name)).await?;

    // Read the output of the hex command
    // Use a longer read timeout and shorter stable duration for commands
    read_until_stable(
        buf,
        pty,
        Duration::from_millis(200),
        Duration::from_millis(50),
    )
    .await?;

    let hex_output = String::from_utf8_lossy(buf);
    // println!("Hex output for {}: \n{}", value_name, hex_output); // Debug

    // Find the relevant line (usually starts with :00000)
    for line in hex_output.lines() {
        // Trim whitespace which might include the prompt ">"
        let trimmed_line = line.trim();
        if trimmed_line.contains(":00000") && trimmed_line.len() > 8 {
            // Extract hex bytes part (adjust indices if needed based on actual chntpw output)
            // Example line: ":00000 XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX ................ >"
            let parts: Vec<&str> = trimmed_line.split_whitespace().collect();
            // Find the start of hex bytes (after :00000) and end (before ASCII representation or prompt)
            let hex_start_index = parts.iter().position(|&p| p.len() == 2).unwrap_or(1); // Start after :00000
            let hex_end_index = parts
                .iter()
                .rposition(|&p| p.len() == 2 && p != ">")
                .map_or(parts.len(), |i| i + 1); // Find last hex byte

            if hex_start_index < hex_end_index {
                let hex_bytes = &parts[hex_start_index..hex_end_index];

                let result = if !reversed {
                    hex_bytes.join("").to_uppercase()
                } else {
                    hex_bytes
                        .iter()
                        .rev()
                        .map(|s| *s)
                        .collect::<Vec<_>>()
                        .join("")
                        .to_uppercase()
                };

                println!("Extracted hex for {}: {}", value_name, result);
                return Ok(Some(result));
            }
        }
    }

    eprintln!(
        "Could not find valid hex data line for value: {}",
        value_name
    );
    Ok(None) // No key found
}

/// Converts a MAC address string without separators to one with colons.
fn format_mac_address(unformatted: &str) -> String {
    unformatted
        .chars()
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(":")
        .to_uppercase()
}

/// Parses the content of a BlueZ info file into sections and key-value pairs.
fn parse_bluez_info(
    content: &str,
) -> std::collections::HashMap<String, std::collections::HashMap<String, String>> {
    let mut data = std::collections::HashMap::new();
    let mut current_section = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed[1..trimmed.len() - 1].to_string();
            data.entry(current_section.clone())
                .or_insert_with(std::collections::HashMap::new);
        } else if !current_section.is_empty() {
            if let Some((key, value)) = trimmed.split_once('=') {
                if let Some(section_map) = data.get_mut(&current_section) {
                    section_map.insert(key.trim().to_string(), value.trim().to_string());
                }
            }
        }
    }
    data
}

/// Formats the parsed BlueZ data back into INI string format.
fn format_bluez_info(
    data: &std::collections::HashMap<String, std::collections::HashMap<String, String>>,
) -> String {
    let mut output = String::new();
    // Consider preserving section order if important, e.g., by using IndexMap
    for (section, map) in data {
        output.push_str(&format!("[{}]\n", section));
        for (key, value) in map {
            output.push_str(&format!("{}={}\n", key, value));
        }
        output.push('\n'); // Add a newline between sections
    }
    output.trim_end().to_string() + "\n" // Ensure single trailing newline
}

// Placeholder for superuser check
fn is_superuser() -> bool {
    // On Unix-like systems:
    unsafe { libc::geteuid() == 0 }
    // On Windows, you'd use windows-rs crate to check for admin privileges
    // For simplicity, returning true, but uncomment the libc version for Linux/macOS
    // true
}

#[tokio::main]
async fn main() -> Result<()> {
    if !is_superuser() {
        // Use eprintln for errors
        eprintln!("Error: This program needs to be run with root/administrator privileges.");
        // Return an error instead of panicking
        return Err(AppError::Command("Insufficient privileges".to_string()));
    }

    // Check for chntpw dependency
    let chntpw_check = std::process::Command::new("sh")
        .arg("-c")
        .arg("which chntpw")
        .output()
        .map_err(|e| AppError::Command(format!("Failed to check for chntpw: {}", e)))?;

    if !chntpw_check.status.success()
        || String::from_utf8_lossy(&chntpw_check.stdout)
            .trim()
            .is_empty()
    {
        eprintln!("Error: 'chntpw' command not found in PATH. Please install it (e.g., 'sudo apt install chntpw' or 'sudo pacman -S chntpw').");
        return Err(AppError::Command("'chntpw' not found".to_string()));
    }
    println!("'chntpw' found.");

    println!("Enter the path to your mounted Windows partition (e.g., /mnt/windows):");
    let mut win_part = String::new();
    std::io::stdin()
        .read_line(&mut win_part)
        .map_err(|e| AppError::Io(e))?; // Convert std::io::Error to AppError
    win_part = win_part.trim().to_string();

    let system_hive_path = Path::new(&win_part).join("Windows/System32/config/SYSTEM");
    if !system_hive_path.exists() {
        eprintln!(
            "Error: SYSTEM hive not found at '{}'. Please check the path.",
            system_hive_path.display()
        );
        return Err(AppError::Config(format!(
            "SYSTEM hive not found at '{}'",
            system_hive_path.display()
        )));
    }
    println!(
        "\nUsing Windows SYSTEM hive at: {}",
        system_hive_path.display()
    );

    println!("Spawning chntpw...");
    let mut binding = Command::new("chntpw");
    let mut command = binding.arg("-e").arg(&system_hive_path); // Pass full path

    let mut pty = Pty::new().map_err(|e| AppError::Pty(format!("Failed to create PTY: {}", e)))?;
    let _child = command // Keep handle to ensure process is reaped later if needed
        .spawn(
            &pty.pts()
                .map_err(|e| AppError::Pty(format!("Failed to get PTY slave: {}", e)))?,
        )
        .map_err(|e| AppError::Command(format!("Could not spawn chntpw: {}", e)))?;

    let mut buf = BytesMut::with_capacity(4096); // Increased buffer size

    // --- Wait for the initial chntpw prompt ---
    println!("Waiting for chntpw prompt...");
    wait_for_prompt(&mut pty, &mut buf, Duration::from_secs(10)).await?;
    let initial_output = String::from_utf8_lossy(&buf);
    println!("Initial chntpw output received:\n{}", initial_output.trim());
    // Buffer now contains startup messages and the prompt "> "

    // --- Find ControlSet ---
    buf.clear(); // Clear buffer before sending command
    send_command(&mut pty, "ls").await?;
    read_until_stable(
        &mut buf,
        &mut pty,
        Duration::from_millis(200),
        Duration::from_millis(50),
    )
    .await?;
    let ls_output = String::from_utf8_lossy(&buf);
    println!("Root 'ls' output:\n{}", ls_output.trim());

    let mut ctrl_set_path: Option<String> = None;
    if ls_output.contains("<CurrentControlSet>") {
        ctrl_set_path = Some("CurrentControlSet\\Services\\BTHPORT\\Parameters\\Keys".to_string());
    } else {
        // Find the first ControlSetXXX entry
        for line in ls_output.lines() {
            if line.contains("<ControlSet") && line.contains('>') {
                let start = line.find('<').unwrap_or(0);
                let end = line.find('>').unwrap_or(line.len());
                if start < end {
                    let name = &line[start + 1..end];
                    ctrl_set_path = Some(format!("{}\\Services\\BTHPORT\\Parameters\\Keys", name));
                    break;
                }
            }
        }
    }

    let ctrl_set_path = ctrl_set_path.ok_or_else(|| {
        AppError::Pty(format!(
            "Could not find CurrentControlSet or ControlSetXXX in chntpw 'ls' output:\n{}",
            ls_output
        ))
    })?;

    println!("Found ControlSet path: {}", ctrl_set_path);

    // --- Navigate to Keys directory ---
    buf.clear();
    send_command(&mut pty, &format!("cd {}", ctrl_set_path)).await?;
    read_until_stable(
        &mut buf,
        &mut pty,
        Duration::from_millis(200),
        Duration::from_millis(50),
    )
    .await?; // Read output/prompt after cd

    // --- List Adapters ---
    println!("Listing Bluetooth adapters (Registry Keys)...");
    buf.clear();
    send_command(&mut pty, "ls").await?;
    read_until_stable(
        &mut buf,
        &mut pty,
        Duration::from_millis(200),
        Duration::from_millis(50),
    )
    .await?;
    let adapters_ls_output = String::from_utf8_lossy(&buf);
    println!("Adapters 'ls' output:\n{}", adapters_ls_output.trim());

    let mut adapters: Vec<BtAdapter> = Vec::new();
    for line in adapters_ls_output.lines() {
        // Adapter keys are directories (no type listed like REG_BINARY)
        if line.contains('<') && line.contains('>') && !line.contains("REG_") {
            let start = line.find('<').unwrap_or(0);
            let end = line.find('>').unwrap_or(line.len());
            if start < end {
                let name = line[start + 1..end].trim().to_string();
                // Basic validation: Check if it looks like a MAC address (12 hex chars)
                if name.len() == 12 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                    println!("Found adapter key: {}", name);
                    adapters.push(BtAdapter {
                        name,
                        devices: Vec::new(),
                    });
                }
            }
        }
    }

    if adapters.is_empty() {
        println!("No Bluetooth adapter keys found in the registry path.");
        // Optionally exit gracefully here if no adapters are found
        // return Ok(());
    } else {
        println!("Found {} potential adapter(s).", adapters.len());
    }

    // --- Process Each Adapter ---
    for adapter in &mut adapters {
        println!(
            "\nProcessing adapter: {}",
            format_mac_address(&adapter.name)
        );
        buf.clear();
        send_command(&mut pty, &format!("cd {}", adapter.name)).await?;
        read_until_stable(
            &mut buf,
            &mut pty,
            Duration::from_millis(200),
            Duration::from_millis(50),
        )
        .await?; // Read output/prompt after cd

        buf.clear();
        send_command(&mut pty, "ls").await?;
        read_until_stable(
            &mut buf,
            &mut pty,
            Duration::from_millis(500), // Allow more time for listing devices
            Duration::from_millis(100),
        )
        .await?;
        let devices_ls_output = String::from_utf8_lossy(&buf);
        println!(
            "Devices/Keys 'ls' output for {}:\n{}",
            format_mac_address(&adapter.name),
            devices_ls_output.trim()
        );

        let mut potential_device_keys = Vec::new();
        let mut potential_device_dirs = Vec::new();

        for line in devices_ls_output.lines() {
            if line.contains('<') && line.contains('>') {
                let start = line.find('<').unwrap_or(0);
                let end = line.find('>').unwrap_or(line.len());
                if start < end {
                    let name = line[start + 1..end].trim().to_string();
                    // Basic validation: Check if it looks like a MAC address (12 hex chars)
                    if name.len() == 12 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                        if line.contains("REG_BINARY") {
                            // Potential legacy key (stored directly under adapter)
                            // Exclude CentralIRK which isn't a device key
                            if !line.contains("CentralIRK") {
                                potential_device_keys.push((name, line.to_string()));
                            }
                        } else {
                            // Potential BT 5.1+ device (stored in subdirectory)
                            potential_device_dirs.push(name);
                        }
                    }
                }
            }
        }

        // Process legacy keys
        for (address, ls_line) in potential_device_keys {
            println!(
                "Processing potential legacy device key: {}",
                format_mac_address(&address)
            );
            match extract_key(&ls_line, &mut pty, &mut buf, false).await? {
                Some(key) => {
                    println!("  -> Found legacy key: {}", key);
                    adapter.devices.push(BtDevice::NonBt51 { address, key });
                }
                None => {
                    eprintln!(
                        "  -> Failed to extract legacy key for {}",
                        format_mac_address(&address)
                    );
                }
            }
        }

        // Process BT 5.1+ devices (directories)
        for address in potential_device_dirs {
            println!(
                "Processing potential BT 5.1+ device dir: {}",
                format_mac_address(&address)
            );
            buf.clear();
            send_command(&mut pty, &format!("cd {}", address)).await?;
            read_until_stable(
                &mut buf,
                &mut pty,
                Duration::from_millis(200),
                Duration::from_millis(50),
            )
            .await?; // Read prompt

            buf.clear();
            send_command(&mut pty, "ls").await?;
            read_until_stable(
                &mut buf,
                &mut pty,
                Duration::from_millis(300),
                Duration::from_millis(50),
            )
            .await?;
            let device_dir_ls_output = String::from_utf8_lossy(&buf).to_string();
            println!(
                "  Contents of {}:\n{}",
                format_mac_address(&address),
                device_dir_ls_output.trim()
            );

            let mut ltk = LongTermKey {
                key: String::new(),
                rand: String::new(),
                ediv: String::new(),
                encsize: None,
            };
            let mut irk: Option<String> = None;
            let mut csrk: Option<String> = None; // CSRK is LocalSignatureKey in BlueZ

            for line in device_dir_ls_output.lines() {
                if !line.contains("REG_BINARY")
                    && !line.contains("REG_DWORD")
                    && !line.contains("REG_QWORD")
                {
                    continue; // Skip non-value lines
                }

                if line.contains("<LTK>") {
                    if let Some(key) = extract_key(&line, &mut pty, &mut buf, false).await? {
                        ltk.key = key;
                    }
                } else if line.contains("<KeyLength>") {
                    // DWORD, little-endian
                    if let Some(hex_val) = extract_key(&line, &mut pty, &mut buf, true).await? {
                        if let Ok(val) = u64::from_str_radix(&hex_val, 16) {
                            ltk.encsize = Some(val.to_string()); // Store as decimal string
                        } else {
                            eprintln!("Failed to parse KeyLength hex: {}", hex_val);
                        }
                    }
                } else if line.contains("<EDIV>") {
                    // WORD (usually stored as DWORD), little-endian
                    if let Some(hex_val) = extract_key(&line, &mut pty, &mut buf, true).await? {
                        // EDIV is u16, but often stored as DWORD. Parse as u64 and convert.
                        if let Ok(val) = u64::from_str_radix(&hex_val, 16) {
                            ltk.ediv = (val as u16).to_string(); // Store as decimal string
                        } else {
                            eprintln!("Failed to parse EDIV hex: {}", hex_val);
                        }
                    }
                } else if line.contains("<ERand>") {
                    // QWORD, little-endian
                    if let Some(hex_val) = extract_key(&line, &mut pty, &mut buf, true).await? {
                        if let Ok(val) = u64::from_str_radix(&hex_val, 16) {
                            ltk.rand = val.to_string(); // Store as decimal string
                        } else {
                            eprintln!("Failed to parse ERand hex: {}", hex_val);
                        }
                    }
                } else if line.contains("<IRK>") && !line.contains("CentralIRK") {
                    // BINARY
                    if let Some(key) = extract_key(&line, &mut pty, &mut buf, false).await? {
                        irk = Some(key);
                    }
                } else if line.contains("<CSRK>") {
                    // BINARY
                    if let Some(key) = extract_key(&line, &mut pty, &mut buf, false).await? {
                        csrk = Some(key);
                    }
                }
            }

            // Check if we got the essential LTK components
            if !ltk.key.is_empty() && !ltk.rand.is_empty() && !ltk.ediv.is_empty() {
                println!(
                    "  -> Found BT 5.1+ keys for {}",
                    format_mac_address(&address)
                );
                adapter.devices.push(BtDevice::Bt51 {
                    address: address.clone(),
                    long_term_key: ltk,
                    identity_resolving_key: irk,
                    local_signature_key: csrk, // CSRK maps to LocalSignatureKey
                });
            } else {
                eprintln!(
                    "  -> Incomplete BT 5.1+ keys found for {}",
                    format_mac_address(&address)
                );
            }

            // Go back up
            buf.clear();
            send_command(&mut pty, "cd ..").await?;
            read_until_stable(
                &mut buf,
                &mut pty,
                Duration::from_millis(200),
                Duration::from_millis(50),
            )
            .await?; // Read prompt
        }

        // Go back up from adapter dir
        buf.clear();
        send_command(&mut pty, "cd ..").await?;
        read_until_stable(
            &mut buf,
            &mut pty,
            Duration::from_millis(200),
            Duration::from_millis(50),
        )
        .await?; // Read prompt
    }

    // --- Exit chntpw ---
    println!("Exiting chntpw...");
    send_command(&mut pty, "q").await?;
    // Optionally wait for the child process to exit
    // let status = child.wait().await?;
    // println!("chntpw exited with status: {:?}", status);

    // --- Save Keys to Linux Filesystem ---
    println!("\n\n--- Saving keys to Linux filesystem ---");
    let base_bluez_path = Path::new("/var/lib/bluetooth");

    for adapter in &adapters {
        let adapter_mac_formatted = format_mac_address(&adapter.name);
        let adapter_path = base_bluez_path.join(&adapter_mac_formatted);
        println!("Adapter path: {}", adapter_path.display());

        if !adapter_path.is_dir() {
            println!(
                "Warning: Adapter directory {} not found in Linux filesystem. Skipping adapter.",
                adapter_path.display()
            );
            continue;
        }

        for device in &adapter.devices {
            let device_mac_formatted = format_mac_address(device.address());
            let device_info_path = adapter_path.join(&device_mac_formatted).join("info");

            println!("Device path: {}", device_info_path.display());

            if device_info_path.is_file() {
                println!("  -> Found existing info file. Reading and updating...");
                let existing_content = tokio::fs::read_to_string(&device_info_path).await?;
                let mut bluez_data = parse_bluez_info(&existing_content);

                // Update sections based on extracted data
                match device {
                    BtDevice::NonBt51 { key, .. } => {
                        let link_key_section = bluez_data.entry("LinkKey".to_string()).or_default();
                        link_key_section.insert("Key".to_string(), key.clone());
                        // Ensure other keys potentially present from BT5+ are removed if switching type
                        bluez_data.remove("LongTermKey");
                        bluez_data.remove("IdentityResolvingKey");
                        bluez_data.remove("LocalSignatureKey");
                    }
                    BtDevice::Bt51 {
                        long_term_key,
                        identity_resolving_key,
                        local_signature_key,
                        ..
                    } => {
                        // Update LongTermKey section
                        let ltk_section = bluez_data.entry("LongTermKey".to_string()).or_default();
                        ltk_section.insert("Key".to_string(), long_term_key.key.clone());
                        ltk_section.insert("Rand".to_string(), long_term_key.rand.clone());
                        ltk_section.insert("EDiv".to_string(), long_term_key.ediv.clone());
                        if let Some(enc_size) = &long_term_key.encsize {
                            ltk_section.insert("EncSize".to_string(), enc_size.clone());
                        } else {
                            // BlueZ usually defaults to 16 if not present, maybe remove?
                            ltk_section.remove("EncSize");
                        }

                        // Update or remove IdentityResolvingKey section
                        if let Some(irk) = identity_resolving_key {
                            let irk_section = bluez_data
                                .entry("IdentityResolvingKey".to_string())
                                .or_default();
                            irk_section.insert("Key".to_string(), irk.clone());
                        } else {
                            bluez_data.remove("IdentityResolvingKey");
                        }

                        // Update or remove LocalSignatureKey section (CSRK)
                        if let Some(csrk) = local_signature_key {
                            let lsk_section = bluez_data
                                .entry("LocalSignatureKey".to_string())
                                .or_default();
                            lsk_section.insert("Key".to_string(), csrk.clone());
                            // BlueZ might also need Counter=0 here? Check bluez source/docs if needed.
                            // lsk_section.insert("Counter".to_string(), "0".to_string());
                        } else {
                            bluez_data.remove("LocalSignatureKey");
                        }

                        // Ensure legacy LinkKey is removed if we have LTK
                        bluez_data.remove("LinkKey");
                    }
                }

                // Write updated content back
                let new_content = format_bluez_info(&bluez_data);
                println!(
                    "  -> Writing updated info file:\n---\n{}---",
                    new_content.trim()
                );
                let mut file = OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&device_info_path)
                    .await?;
                file.write_all(new_content.as_bytes()).await?;
                println!("  -> Successfully updated {}", device_info_path.display());
            } else {
                println!(
                    "  -> Info file not found. Device {} might not be paired on Linux yet. Skipping.",
                    device_mac_formatted
                );
            }
        }
    }

    // --- Restart Bluetooth Service ---
    println!("\n--- Restarting Bluetooth service ---");
    // Use systemctl only if it exists
    let systemctl_check = std::process::Command::new("sh")
        .arg("-c")
        .arg("which systemctl")
        .output()
        .map_err(|e| AppError::Command(format!("Failed to check for systemctl: {}", e)))?;

    if systemctl_check.status.success() && !systemctl_check.stdout.is_empty() {
        let output = std::process::Command::new("systemctl")
            .arg("restart")
            .arg("bluetooth")
            .output()
            .map_err(|e| AppError::Command(format!("Failed to run systemctl: {}", e)))?;

        println!("systemctl output:");
        println!("Status: {}", output.status);
        if !output.stdout.is_empty() {
            println!("Stdout: {}", String::from_utf8_lossy(&output.stdout).trim());
        }
        if !output.stderr.is_empty() {
            println!("Stderr: {}", String::from_utf8_lossy(&output.stderr).trim());
        }

        if !output.status.success() {
            eprintln!("Warning: Failed to restart bluetooth service via systemctl. You may need to restart it manually or reboot.");
        } else {
            println!("Bluetooth service restarted successfully.");
        }
    } else {
        println!("'systemctl' not found. Please restart the Bluetooth service manually (e.g., 'sudo service bluetooth restart' or reboot).");
    }

    println!("\n--- Done ---");
    println!("Keys have been extracted and applied where possible.");
    println!("If devices don't connect automatically, a reboot might be required.");

    Ok(())
}
