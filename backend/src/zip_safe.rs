//! Bounded ZIP reading shared by every site that decompresses an archive
//! (catalog uploads, library import, DISA sync, backup restore).
//!
//! Two limits apply: a per-entry cap and a cumulative per-request budget that
//! is carried through nested archives. Every archive is also checked with
//! `validate_header_consistency()` before any entry is read, so a central
//! directory that disagrees with the local headers, duplicate names,
//! overlapping entries and unlisted local headers are all refused.

use std::fmt;
use std::io::{Cursor, Read};

/// Cumulative decompressed-byte budget for one request.
#[derive(Debug)]
pub struct ReadBudget {
    limit: u64,
    used: u64,
}

impl ReadBudget {
    pub fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    #[cfg(test)]
    pub fn used(&self) -> u64 {
        self.used
    }
}

#[derive(Debug)]
pub enum ZipReadError {
    /// A single entry is larger than its cap.
    EntryTooLarge {
        name: String,
        limit: u64,
    },
    /// The request-wide budget is exhausted.
    BudgetExceeded {
        limit: u64,
    },
    /// `validate_header_consistency()` failed.
    Inconsistent(String),
    NoXccdf,
    Zip(zip::result::ZipError),
    Io(std::io::Error),
}

impl ZipReadError {
    /// True for the errors that mean "too big" (HTTP 413).
    pub fn is_limit(&self) -> bool {
        matches!(
            self,
            Self::EntryTooLarge { .. } | Self::BudgetExceeded { .. }
        )
    }

    /// Stable machine-readable reason, used in audit records.
    pub fn code(&self) -> &'static str {
        match self {
            Self::EntryTooLarge { .. } => "entry_too_large",
            Self::BudgetExceeded { .. } => "budget_exceeded",
            Self::Inconsistent(_) => "header_inconsistency",
            Self::NoXccdf => "no_xccdf",
            Self::Zip(_) | Self::Io(_) => "malformed",
        }
    }
}

impl fmt::Display for ZipReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntryTooLarge { name, limit } => {
                write!(f, "entry {name} is larger than {limit} bytes uncompressed")
            }
            Self::BudgetExceeded { limit } => {
                write!(f, "archive is larger than {limit} bytes uncompressed")
            }
            Self::Inconsistent(m) => write!(f, "inconsistent ZIP headers: {m}"),
            Self::NoXccdf => write!(f, "No *_xccdf.xml found in ZIP archive"),
            Self::Zip(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ZipReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Zip(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<zip::result::ZipError> for ZipReadError {
    fn from(e: zip::result::ZipError) -> Self {
        Self::Zip(e)
    }
}

impl From<std::io::Error> for ZipReadError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Entry name for an error message: at most 64 characters, `{:?}`-escaped.
fn display_name(name: &str) -> String {
    format!("{:?}", name.chars().take(64).collect::<String>())
}

/// `ZipArchive::new` followed by `validate_header_consistency()`.
pub fn open_validated(bytes: &[u8]) -> Result<zip::ZipArchive<Cursor<&[u8]>>, ZipReadError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    archive
        .validate_header_consistency()
        .map_err(|e| ZipReadError::Inconsistent(e.to_string()))?;
    Ok(archive)
}

/// Read `r` to the end under `entry_limit` and the shared `budget`.
///
/// A `declared` size over the limit is refused without decompressing. The
/// read never overshoots the budget by more than one byte, and every byte read
/// (including those of a rejected entry) is charged to the budget.
pub fn read_capped(
    r: &mut impl Read,
    name: &str,
    declared: Option<u64>,
    entry_limit: u64,
    budget: &mut ReadBudget,
) -> Result<Vec<u8>, ZipReadError> {
    if declared.is_some_and(|d| d > entry_limit) {
        return Err(ZipReadError::EntryTooLarge {
            name: display_name(name),
            limit: entry_limit,
        });
    }
    let allowed = entry_limit.min(budget.remaining());
    let mut buf = Vec::new();
    let res = r.take(allowed.saturating_add(1)).read_to_end(&mut buf);
    // Charge what was delivered even when the read then fails (the zip crate
    // reports a bad CRC only at EOF, after every byte was decompressed).
    let n = buf.len() as u64;
    budget.used = budget.used.saturating_add(n);
    res?;
    if n > allowed {
        // Which cap was hit? The entry cap wins when it is the tighter one.
        return Err(if n > entry_limit {
            ZipReadError::EntryTooLarge {
                name: display_name(name),
                limit: entry_limit,
            }
        } else {
            ZipReadError::BudgetExceeded {
                limit: budget.limit,
            }
        });
    }
    Ok(buf)
}

/// `read_capped` taking the name and declared size from a ZIP entry.
pub fn read_entry<R: Read>(
    entry: &mut zip::read::ZipFile<'_, R>,
    entry_limit: u64,
    budget: &mut ReadBudget,
) -> Result<Vec<u8>, ZipReadError> {
    let name = entry.name().map(|n| n.into_owned()).unwrap_or_default();
    let declared = entry.size();
    read_capped(entry, &name, Some(declared), entry_limit, budget)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::{write::SimpleFileOptions, ZipWriter};

    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        for (n, d) in entries {
            w.start_file(*n, SimpleFileOptions::default()).unwrap();
            w.write_all(d).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn at_cap_passes_and_one_over_fails() {
        let mut b = ReadBudget::new(100);
        assert_eq!(
            read_capped(&mut &b"abc"[..], "e", None, 3, &mut b).unwrap(),
            b"abc"
        );
        let mut b = ReadBudget::new(100);
        let e = read_capped(&mut &b"abcd"[..], "e", None, 3, &mut b).unwrap_err();
        assert!(
            matches!(e, ZipReadError::EntryTooLarge { limit: 3, .. }),
            "{e}"
        );
        assert!(e.is_limit());
        assert_eq!(e.code(), "entry_too_large");
    }

    #[test]
    fn declared_over_cap_is_refused_without_reading() {
        struct Boom;
        impl Read for Boom {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("must not read");
            }
        }
        let mut b = ReadBudget::new(100);
        let e = read_capped(&mut Boom, "e", Some(4), 3, &mut b).unwrap_err();
        assert!(matches!(e, ZipReadError::EntryTooLarge { .. }));
        assert_eq!(b.used(), 0);
    }

    #[test]
    fn budget_is_shared_across_reads_and_charged_for_rejects() {
        let mut b = ReadBudget::new(5);
        assert!(read_capped(&mut &b"abc"[..], "a", None, 10, &mut b).is_ok());
        assert_eq!(b.remaining(), 2);
        let e = read_capped(&mut &b"abc"[..], "b", None, 10, &mut b).unwrap_err();
        assert!(
            matches!(e, ZipReadError::BudgetExceeded { limit: 5 }),
            "{e}"
        );
        assert_eq!(e.code(), "budget_exceeded");
        // 2 bytes allowed + 1 probe byte were read and charged.
        assert_eq!(b.used(), 6);
        assert_eq!(b.remaining(), 0);
        assert!(read_capped(&mut &b"x"[..], "c", None, 10, &mut b).is_err());
    }

    #[test]
    fn bytes_read_before_an_error_are_still_charged() {
        struct ThenErr(u64);
        impl Read for ThenErr {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    return Err(std::io::Error::other("Invalid checksum"));
                }
                let n = (self.0 as usize).min(out.len());
                out[..n].fill(b' ');
                self.0 -= n as u64;
                Ok(n)
            }
        }
        let mut b = ReadBudget::new(1000);
        let e = read_capped(&mut ThenErr(40), "e", None, 100, &mut b).unwrap_err();
        assert!(matches!(e, ZipReadError::Io(_)), "{e}");
        assert_eq!(b.used(), 40);
    }

    #[test]
    fn long_names_are_truncated_and_escaped() {
        let long = "a\n".repeat(100);
        let mut b = ReadBudget::new(100);
        let e = read_capped(&mut &b"abcd"[..], &long, None, 3, &mut b).unwrap_err();
        let msg = e.to_string();
        assert!(!msg.contains('\n'), "{msg}");
        assert!(msg.len() < 200, "{msg}");
    }

    #[test]
    fn open_validated_accepts_a_well_formed_archive() {
        let z = zip_of(&[("a.txt", b"hello"), ("b.txt", b"world")]);
        assert_eq!(open_validated(&z).unwrap().len(), 2);
    }

    #[test]
    fn open_validated_rejects_a_central_only_name_patch() {
        let mut z = zip_of(&[("a.txt", b"hello")]);
        let cd = z.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        // Central directory file name starts at offset 46.
        z[cd + 46] = b'b';
        let e = open_validated(&z).err().unwrap();
        assert!(matches!(e, ZipReadError::Inconsistent(_)), "{e}");
        assert_eq!(e.code(), "header_inconsistency");
    }

    #[test]
    fn open_validated_rejects_a_central_only_size_patch() {
        let mut z = zip_of(&[("a.txt", b"hello world")]);
        let cd = z.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        z[cd + 24..cd + 28].copy_from_slice(&3u32.to_le_bytes());
        let e = open_validated(&z).err().unwrap();
        assert!(matches!(e, ZipReadError::Inconsistent(_)), "{e}");
    }

    #[test]
    fn open_validated_rejects_duplicate_names() {
        let mut z = zip_of(&[("a.txt", b"one"), ("b.txt", b"two")]);
        // Rename b.txt to a.txt in both the local and central headers.
        for pos in 0..z.len() - 4 {
            if &z[pos..pos + 4] == b"PK\x03\x04" {
                let n = pos + 30;
                if &z[n..n + 5] == b"b.txt" {
                    z[n] = b'a';
                }
            } else if &z[pos..pos + 4] == b"PK\x01\x02" {
                let n = pos + 46;
                if &z[n..n + 5] == b"b.txt" {
                    z[n] = b'a';
                }
            }
        }
        let e = open_validated(&z).err().unwrap();
        // validate_header_consistency() reports duplicate names; ZipArchive::new accepts them.
        assert!(matches!(e, ZipReadError::Inconsistent(_)), "{e}");
    }

    #[test]
    fn read_entry_enforces_the_cap() {
        let z = zip_of(&[("a.txt", &[b'x'; 50])]);
        let mut ar = open_validated(&z).unwrap();
        let mut b = ReadBudget::new(1000);
        let mut f = ar.by_index(0).unwrap();
        let e = read_entry(&mut f, 10, &mut b).unwrap_err();
        assert!(matches!(e, ZipReadError::EntryTooLarge { .. }));
        let mut ar = open_validated(&z).unwrap();
        let mut f = ar.by_index(0).unwrap();
        assert_eq!(read_entry(&mut f, 50, &mut b).unwrap().len(), 50);
    }
}
