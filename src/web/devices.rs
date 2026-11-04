//! Enumerate the storage devices a guardian can keep shards on: this computer
//! plus any connected USB drives. The web UI uses this to populate the device
//! selector shown next to each shard/share password field.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub root: String,
}

pub fn list() -> Vec<Device> {
    #[cfg(windows)]
    let mut devices = windows_devices::list();

    #[cfg(not(windows))]
    let mut devices = Vec::new();

    if !devices.iter().any(|device| device.kind == "computer") {
        devices.insert(0, local_device());
    }

    devices
}

fn local_device() -> Device {
    #[cfg(windows)]
    let root = format!(
        "{}\\",
        std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string())
    );

    #[cfg(not(windows))]
    let root = "/".to_string();

    let drive = root.trim_end_matches(['\\', '/']);

    Device {
        id: root.clone(),
        label: format!("This computer ({drive})"),
        kind: "computer".to_string(),
        root,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn lists_the_local_computer_first() {
        let devices = super::list();

        assert!(!devices.is_empty());
        assert_eq!(devices[0].kind, "computer");
        assert!(devices.iter().all(|device| !device.label.is_empty()));
    }
}

#[cfg(windows)]
mod windows_devices {
    use super::Device;
    use windows_sys::Win32::Storage::FileSystem::{
        GetDriveTypeW, GetLogicalDriveStringsW, GetVolumeInformationW,
    };

    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;

    pub fn list() -> Vec<Device> {
        let needed = unsafe { GetLogicalDriveStringsW(0, std::ptr::null_mut()) };
        if needed == 0 {
            return Vec::new();
        }

        let mut buffer = vec![0u16; needed as usize + 1];
        let written = unsafe { GetLogicalDriveStringsW(buffer.len() as u32, buffer.as_mut_ptr()) };
        if written == 0 {
            return Vec::new();
        }

        let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());

        let mut devices = Vec::new();
        let mut start = 0usize;

        for index in 0..written as usize {
            if buffer[index] != 0 {
                continue;
            }
            if index == start {
                break;
            }

            let root = String::from_utf16_lossy(&buffer[start..index]);
            start = index + 1;

            let drive = root.trim_end_matches('\\').to_ascii_uppercase();
            let mut wide: Vec<u16> = root.encode_utf16().collect();
            wide.push(0);

            let drive_type = unsafe { GetDriveTypeW(wide.as_ptr()) };
            let is_system = drive.eq_ignore_ascii_case(&system_drive);

            let (kind, prefix) = if is_system {
                ("computer", "This computer")
            } else if drive_type == DRIVE_REMOVABLE {
                ("usb", "USB drive")
            } else if drive_type == DRIVE_FIXED {
                ("drive", "Drive")
            } else {
                continue;
            };

            let volume = volume_label(&wide);
            let label = if volume.is_empty() {
                format!("{prefix} ({drive})")
            } else {
                format!("{prefix} \u{2014} {volume} ({drive})")
            };

            devices.push(Device {
                id: root.clone(),
                label,
                kind: kind.to_string(),
                root,
            });
        }

        devices.sort_by(|a, b| {
            let rank = |kind: &str| match kind {
                "computer" => 0,
                "usb" => 1,
                _ => 2,
            };
            rank(&a.kind)
                .cmp(&rank(&b.kind))
                .then_with(|| a.label.cmp(&b.label))
        });

        devices
    }

    fn volume_label(root: &[u16]) -> String {
        let mut buffer = [0u16; 256];
        let ok = unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        };

        if ok == 0 {
            return String::new();
        }

        let len = buffer.iter().position(|c| *c == 0).unwrap_or(0);
        String::from_utf16_lossy(&buffer[..len])
    }
}
