use std::io;

use itertools::Itertools;
use rustyline::error::ReadlineError;
use rustyline::{DefaultEditor, Result};

fn find_password(hash: Vec<u8>) -> String {
    let chars = "abcdefghijklmnopqrstuvwxyz0123456789".as_bytes();
    let chars = Vec::from(chars);

    let perms = chars.into_iter().permutations(6);

    for v in perms {
        let h = Vec::from(md5::compute(&v).as_slice());
        if h == hash {
            return String::from_utf8(v).expect("Failed while converting found password!");
        }
    }

    String::new()
}

fn check_line(mut line: String, sem: u8) -> Result<Vec<u8>> {
    match sem {
        b'p' => {
            if line.len() > 6 {
                println!("Your password is longer then 6 bytes, so it has been cut!");
                line.drain(6..);
                println!("Now your password is {line}");
            }

            let mut pswd = [b'a'; 6];

            for (i, c) in line.as_bytes().iter().enumerate() {
                if !c.is_ascii_alphanumeric() {
                    return Err(ReadlineError::Eof);
                } else if c.is_ascii_uppercase() {
                    pswd[i] = c.to_ascii_lowercase();
                    println!("Only lowercase symbols are acceptable, and {c} is in uppercase, so it was lowered.");
                } else {
                    pswd[i] = *c;
                }
            }
            Ok(Vec::from(pswd))
        }
        b'h' => {
            if line.len() > 32 {
                println!("Hash contains too many symbols, so it has been cut!");
                line.drain(32..);
            }

            let mut hash = [b'a'; 32];
            for (i, c) in line.as_bytes().iter().enumerate() {
                if !c.is_ascii_alphanumeric() {
                    return Err(ReadlineError::Eof);
                } else if c.is_ascii_uppercase() {
                    hash[i] = c.to_ascii_lowercase();
                    println!("Only lowercase symbols are acceptable, and {c} is in uppercase, so it was lowered.");
                } else {
                    hash[i] = *c;
                }
            }

            Ok(Vec::from(hash))
        }
        _ => Err(ReadlineError::Eof),
    }
}

fn parse_hash(s: Vec<u8>) -> Vec<u8> {
    let s1 = String::from_utf8(s).expect("Failed to parse hash");
    let mut hash: [u8; 16] = [0; 16];
    let mut i = 0;
    let mut i2 = 0;

    while i < 32 {
        match u8::from_str_radix(&s1[i..i + 2], 16) {
            Ok(n) => {
                hash[i2] = n;
                i += 2;
                i2 += 1;
            }
            Err(_) => {}
        };
    }

    Vec::from(hash)
}

fn main() -> Result<()> {
    println!("Following options are avaluable:");
    println!(":q -- quit");
    println!(":p -- input password");
    println!(":h -- input hash-sum");
    let mut rl = DefaultEditor::new()?;
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => match &line[..] {
                ":p" => {
                    println!("Input 6 symbol password. Allowed symbols are: a-z, 0-9");
                    let password = rl.readline(">> ")?;
                    let password = check_line(password, b'p')?;
                    let digest = md5::compute(password);
                    println!("Hash-sum for the password is: {:?}", digest);
                }
                ":h" => {
                    println!("Input 32 symbols of hash-sum:");
                    let hash = rl.readline(">> ")?;
                    let hash = check_line(hash, b'h')?;
                    let pswd = find_password(parse_hash(hash));
                    println!("The found password is: {:?}", pswd);
                }
                ":q" => {
                    println!("Quit!");
                    break;
                }
                _ => {
                    println!("Error: unknown option {}!", line);
                }
            },
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }

    Ok(())
}