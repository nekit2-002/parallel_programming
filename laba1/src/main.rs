use rustyline::error::ReadlineError;
use rustyline::{DefaultEditor, Result};
use itertools::Itertools;

fn find_password(hash:[u8; 16]) -> Vec<u8> {
    let h = &hash[..];
    let chars = "abcdefghijklmnopqrstuvwxyz0123456789".as_bytes();
    let chars = Vec::from(chars);

    let perms = chars.into_iter().permutations(6);

    let mut pswd = Vec::new();
    for v in perms {
        if md5::compute(&v).as_slice() == h {
            pswd = v;
            break;
        } else {continue;}
    }

    pswd
}

fn check_password(mut password: String) -> Result<[u8; 6]> {
    if password.len() > 6 {
        println!("Your password is longer then 6 bytes, so it has been cut!");
        password.drain(6..);
        println!("Now your password is {password}");
    }

    let mut pswd =[b'a'; 6];
    for (i, c) in password.as_bytes().iter().enumerate() {
        if !c.is_ascii_alphanumeric(){
            return Err(ReadlineError::Eof);
        } else if c.is_ascii_uppercase() {
            pswd[i] = c.to_ascii_lowercase();
            println!("Only lowercase symbols are acceptable, and {c} is in uppercase, so it was lowered.");
        } else {
            pswd[i] = *c;
        }
    }

    Ok(pswd)
}

fn parse_hash(s: String) -> [u8; 16] {
    let mut hash: [u8; 16] = [0;16];
    let mut i = 0;
    let mut i2 = 0;

    while i < 32 {
        match u8::from_str_radix(&s[i..i+2], 16) {
            Ok(n) => {
                hash[i2] = n;
                i += 2;
                i2 += 1;
            },
            Err(_) => return hash
        };
    }

    hash
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
            Ok(line) => {
                match &line[..] {
                    ":p" => {
                        println!("Input 6 symbol password. Allowed symbols are: a-z, 0-9");
                        let password = rl.readline(">> ")?;
                        let password = check_password(password)?;
                        let digest = md5::compute(password);
                        println!("Hash-sum for the password is: {:?}", digest);
                        println!("Hash-sum for the password is: {:?}", digest.as_slice());
                    },
                    ":h" => {
                        println!("Input 32 symbols of hash-sum:");
                        let hash = rl.readline(">> ")?;
                        println!("Hash-sum now is {hash}");
                        let pswd = find_password(parse_hash(hash));
                        println!("The found password is: {:?}", pswd.as_slice());
                        
                    },
                    ":q" => {
                        println!("Quit!");
                        break
                    },
                    _ => {
                        println!("Error: unknown option {}!", line);
                    }
                }
            },
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break
            },
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break
            },
            Err(err) => {
                println!("Error: {:?}", err);
                break
            }
        }
    }

    Ok(())
}