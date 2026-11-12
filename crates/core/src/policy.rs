// SPDX-License-Identifier: AGPL-3.0-only
//! Password policy for NEW passwords (vault creation, password change), following
//! NIST SP 800-63B-4 and OWASP guidance:
//!   * length is what matters: at least 15 characters (the password is the only factor
//!     protecting an offline-attackable vault), up to 1024, spaces and any Unicode allowed;
//!   * NO composition rules ("must contain a symbol"), NO expiry;
//!   * reject passwords that are on a blocklist of common / famous / context-specific values
//!     or that follow trivial patterns (repeats, keyboard or alphabet runs, very few distinct characters).
//!
//! Unlocking an existing vault is never subject to this policy (older, shorter passwords keep working).
use crate::crypto::MAX_PASSWORD_CHARS;
use crate::error::{Result, VaultError};
use unicode_normalization::UnicodeNormalization;

pub const MIN_NEW_PASSWORD_CHARS: usize = 15;

/// Lowercase, letters+digits only. Words/phrases that must never be (the core of) a password.
const COMMON: &[&str] = &[
    "password",
    "passw0rd",
    "p4ssw0rd",
    "passphrase",
    "mypassword",
    "letmein",
    "welcome",
    "iloveyou",
    "admin",
    "administrator",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "master",
    "sunshine",
    "princess",
    "shadow",
    "superman",
    "batman",
    "trustno1",
    "login",
    "starwars",
    "whatever",
    "freedom",
    "hello",
    "secret",
    "secure",
    "notes",
    "ctrlaltnotes",
    "vault",
    "changeme",
    "default",
    "qwerty",
    "qwertyuiop",
    "qwertyuiopasdfghjkl",
    "asdfghjkl",
    "zxcvbnm",
    "1q2w3e4r",
    "1qaz2wsx",
    "abc123",
    "abcdefgh",
    "abcdefghijklmnopqrstuvwxyz",
    "letmein123",
    "iloveyou123",
    "correcthorsebatterystaple",
    "thequickbrownfoxjumpsoverthelazydog",
    "horsebatterystaple",
    "opensesame",
    "welcome123",
    "monkey123",
    "internet",
    "computer",
    "michael",
    "jennifer",
];

/// Words that, alone or glued together with digits/symbols, make a password guessable.
const FILLER: &[&str] = &[
    "january",
    "february",
    "march",
    "april",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
    "spring",
    "summer",
    "autumn",
    "winter",
    "fall",
    "monday",
    "friday",
    "sunday",
    "love",
    "life",
    "home",
    "family",
    "user",
    "test",
    "guest",
    "root",
    "account",
    "pass",
    "word",
    "my",
    "the",
    "and",
    "abc",
    "qwe",
    "asd",
    "zxc",
    "good",
    "happy",
    "lucky",
    "super",
    "ninja",
    "cool",
    "king",
    "queen",
    "angel",
    "tiger",
    "soccer",
    "hockey",
    "ranger",
    "google",
    "apple",
    "amazon",
    "facebook",
    "twitter",
    "netflix",
];

/// Keyboard layouts walked in rows, columns and zig-zags (forward; reversed is checked too).
const WALKS: &[&str] = &[
    "qwertyuiopasdfghjklzxcvbnm",
    "1234567890",
    "1q2w3e4r5t6y7u8i9o0p",
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p",
    "zaq12wsxcde34rfvbgt56yhnmju78ik9ol0p",
    "qazwsxedcrfvtgbyhnujmikolp",
    "azertyuiopqsdfghjklmwxcvbn",
    "0123456789",
    "abcdefghijklmnopqrstuvwxyz",
];

/// Fold common "leetspeak" substitutions so P@ssw0rd and password are the same word.
fn fold_leet(s: &str) -> String {
    fold(s, true)
}

/// `all == false` maps only the unambiguous letter look-alikes (0 3 4 5 7 @ $), so that digit
/// and symbol padding (`1`, `!`, `+`) is dropped instead of becoming letters.
fn fold(s: &str, all: bool) -> String {
    s.nfkc()
        .flat_map(|c| c.to_lowercase())
        .map(|c| match c {
            '0' => 'o',
            '1' | '!' | '|' if all => 'i',
            '3' => 'e',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            '7' => 't',
            '+' if all => 't',
            '8' if all => 'b',
            _ => c,
        })
        .filter(|c| c.is_alphanumeric())
        .collect()
}

/// Share (in tenths) of `s` covered by runs (>= 6) taken from keyboard/alphabet/number walks.
fn walk_coverage(s: &[char]) -> usize {
    let mut covered = vec![false; s.len()];
    for w in WALKS {
        let fwd: Vec<char> = w.chars().collect();
        let rev: Vec<char> = fwd.iter().rev().copied().collect();
        for src in [&fwd, &rev] {
            for i in 0..s.len() {
                for j in 0..src.len() {
                    let mut k = 0;
                    while i + k < s.len() && j + k < src.len() && s[i + k] == src[j + k] {
                        k += 1;
                    }
                    if k >= 6 {
                        covered[i..i + k].iter_mut().for_each(|c| *c = true);
                    }
                }
            }
        }
    }
    covered.iter().filter(|c| **c).count() * 10
}

/// A block that is repeated, possibly with a truncated copy at the end:
/// `Summer2024Summer`, `Passw0rd!Passw0rd!`.
fn block_repeat(s: &[char]) -> bool {
    let n = s.len();
    (4..=n / 2).any(|b| s[..b] == s[n - b..] && 2 * b * 10 >= n * 7)
}

fn alnum_lower(s: &str) -> String {
    s.nfkc()
        .flat_map(|c| c.to_lowercase())
        .filter(|c| c.is_alphanumeric())
        .collect()
}

fn is_period_repeat(s: &[char]) -> bool {
    (1..=4).any(|p| s.len() >= 2 * p && s.iter().enumerate().all(|(i, c)| *c == s[i % p]))
}

fn mostly_sequential(s: &[char]) -> bool {
    if s.len() < 6 {
        return false;
    }
    let steps = s.windows(2).filter(|w| {
        let d = w[1] as i64 - w[0] as i64;
        d == 1 || d == -1
    });
    steps.count() * 10 >= (s.len() - 1) * 8
}

/// Is this (NFKC-normalised) password acceptable for a NEW vault password?
pub fn check_new_password(password: &str) -> Result<()> {
    let norm: String = password.nfkc().collect();
    let n = norm.chars().count();
    if n < MIN_NEW_PASSWORD_CHARS {
        return Err(VaultError::other(format!(
            "use at least {MIN_NEW_PASSWORD_CHARS} characters (a passphrase of several unrelated words works well)"
        )));
    }
    if n > MAX_PASSWORD_CHARS {
        return Err(VaultError::other(format!(
            "at most {MAX_PASSWORD_CHARS} characters"
        )));
    }
    let core = alnum_lower(&norm);
    let letters: String = core.chars().filter(|c| !c.is_ascii_digit()).collect();
    let chars: Vec<char> = core.chars().collect();
    let distinct = {
        let mut v: Vec<char> = norm.chars().collect();
        v.sort_unstable();
        v.dedup();
        v.len()
    };
    let weak = || {
        VaultError::other(
            "too easy to guess: use a longer passphrase of unrelated words, or a random password",
        )
    };
    if distinct < 8 || is_period_repeat(&chars) || mostly_sequential(&chars) {
        return Err(weak());
    }
    // all digits, repeated blocks, keyboard/alphabet walks
    if letters.is_empty() || block_repeat(&chars) || walk_coverage(&chars) >= chars.len() * 6 {
        return Err(weak());
    }
    // the same checks after folding leetspeak, and "only common words + digits/symbols"
    let folded = fold_leet(&norm);
    let fchars: Vec<char> = folded.chars().collect();
    if block_repeat(&fchars) || is_period_repeat(&fchars) {
        return Err(weak());
    }
    let mut words: Vec<&str> = COMMON.iter().chain(FILLER.iter()).copied().collect();
    words.sort_by_key(|w| std::cmp::Reverse(w.len()));
    for all in [true, false] {
        let mut residue = fold(&norm, all);
        for w in &words {
            residue = residue.replace(&fold(w, all), "");
        }
        residue.retain(|c| !c.is_ascii_digit());
        if residue.chars().count() <= 4 {
            return Err(weak());
        }
    }
    for w in COMMON {
        // the password is essentially just a common word (optionally repeated / with digits added)
        let repeats = !letters.is_empty()
            && letters.len() % w.len() == 0
            && letters == w.repeat(letters.len() / w.len());
        let fw = fold_leet(w);
        if core == *w || letters == *w || repeats || folded == fw {
            return Err(weak());
        }
        // a very common word padded with little else
        if (core.contains(w) || folded.contains(&fw)) && w.len() >= 6 && folded.len() <= w.len() + 4
        {
            return Err(weak());
        }
    }
    Ok(())
}
