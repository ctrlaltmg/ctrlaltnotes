// SPDX-License-Identifier: AGPL-3.0-only
//! A tiny, dependency-free ZIP writer ("stored" entries, no compression) used by the web
//! version's export download. Names are UTF-8, sizes are capped well below ZIP64 territory.
use crate::error::{Result, VaultError};

const MAX_TOTAL: usize = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 20_000;

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    let mut crc = !0u32;
    for b in data {
        crc = table[((crc ^ *b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

/// (DOS time, DOS date) for a unix timestamp in seconds. ZIP cannot represent years < 1980.
fn dos_datetime(unix_secs: i64) -> (u16, u16) {
    let days = unix_secs.div_euclid(86_400);
    let rem = unix_secs.rem_euclid(86_400);
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    let y = y.clamp(1980, 2107);
    let time = ((rem / 3600) << 11) | (((rem % 3600) / 60) << 5) | ((rem % 60) / 2);
    let date = ((y - 1980) << 9) | (m << 5) | d;
    (time as u16, date as u16)
}

/// Build a ZIP archive. A name ending in `/` is a directory entry (its data must be empty).
pub fn build(entries: &[(String, Vec<u8>)], unix_secs: i64) -> Result<Vec<u8>> {
    if entries.len() > MAX_ENTRIES {
        return Err(VaultError::other("too many files to export at once"));
    }
    let total: usize = entries.iter().map(|(n, d)| n.len() + d.len()).sum();
    if total > MAX_TOTAL {
        return Err(VaultError::other("the selection is too large to download"));
    }
    let (time, date) = dos_datetime(unix_secs);
    let mut out: Vec<u8> = Vec::with_capacity(total + entries.len() * 100 + 64);
    let mut central: Vec<u8> = Vec::new();
    for (name, data) in entries {
        let is_dir = name.ends_with('/');
        if name.is_empty() || name.len() > 1024 || (is_dir && !data.is_empty()) {
            return Err(VaultError::other("invalid export entry"));
        }
        let crc = crc32(data);
        let offset = out.len() as u32;
        let size = data.len() as u32;
        let nlen = name.len() as u16;
        // local file header
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0x0800u16.to_le_bytes()); // flags: UTF-8 names
        out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        out.extend_from_slice(&time.to_le_bytes());
        out.extend_from_slice(&date.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        // central directory entry
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&((3u16 << 8) | 20).to_le_bytes()); // made by: Unix, 2.0
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0x0800u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&time.to_le_bytes());
        central.extend_from_slice(&date.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&nlen.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        let mode: u32 = if is_dir { 0o040_755 } else { 0o100_644 };
        central.extend_from_slice(&(mode << 16).to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_off = out.len() as u32;
    let cd_len = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn dos_date_is_sane() {
        // 2024-02-29 12:34:56 UTC = 1709210096
        let (t, d) = dos_datetime(1_709_210_096);
        assert_eq!(d >> 9, 2024 - 1980);
        assert_eq!((d >> 5) & 15, 2);
        assert_eq!(d & 31, 29);
        assert_eq!(t >> 11, 12);
        assert_eq!((t >> 5) & 63, 34);
    }

    #[test]
    fn rejects_oversize_and_bad_entries() {
        assert!(build(&[("a/".into(), vec![1])], 0).is_err());
        assert!(build(&[(String::new(), vec![])], 0).is_err());
        assert!(build(&[("x.md".into(), vec![0; MAX_TOTAL + 1])], 0).is_err());
    }
}
