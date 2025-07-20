/*
Design a newtype, Password, representing a user's password.

The Password constructor should ensure that passwords submitted by users are at least 8 ASCIl characters long – any other password policy you'd like to enforce is up to you!

In real-life code, we want to minimise the time that user passwords are exposed as human-readable strings. A classic mistake is logging raw passwords accidentally. With this in mind, Password should not hold onto the user-submitted string, but should store a hash instead.
*/
use std::hash::{DefaultHasher, Hash, Hasher};
use thiserror::Error;

#[derive(Debug, Hash)]
pub struct Password(String);

#[derive(Error, Debug, PartialEq)]
pub enum PasswordError {
    #[error("Password should be at least 8 chars long, but was {0}")]
    length(usize),
    #[error("Password should be a valid string {0}")]
    conversion(String),
}

impl Password {
    pub fn new(password: &str) -> Result<Password, PasswordError> {
        let pwd_length: usize = password.len();

        if pwd_length < 8 {
            return Err(PasswordError::length(pwd_length));
        }

        let mut hasher: DefaultHasher = DefaultHasher::new();
        password.hash(&mut hasher);
        let hashed_pwd: u64 = hasher.finish();
        let hashed_pwd_str: String = hashed_pwd.to_string();

        Ok(Self(hashed_pwd_str))
    }
}

fn main() {
    let pwd = Password::new("<PASSWORD>").unwrap();

    println!("Hello, world! {:#?}", pwd.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_new() {
        let pwd = Password::new("<PASSWORD>");
        assert!(pwd.is_ok());
        let password = pwd.unwrap();
        assert_ne!(password.0.len(), 0); // Make sure there's a hash
    }

    #[test]
    fn test_password_too_short() {
        let pwd = Password::new("less");
        assert!(pwd.is_err());
    }

    #[test]
    fn test_password_duplicate_hash() {
        let raw_pwd: String = String::from("<PASSWORD>");
        let pwd = Password::new(&raw_pwd);
        assert!(pwd.is_ok());
        let second_pwd = Password::new(&raw_pwd);
        assert!(second_pwd.is_ok());

        assert_eq!(pwd.unwrap().0, second_pwd.unwrap().0);
    }
}
