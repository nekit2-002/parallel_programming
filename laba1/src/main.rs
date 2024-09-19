use itertools::iproduct;
use rustyline::error::ReadlineError;
use rustyline::{DefaultEditor, Result};
use std::io::{Error, ErrorKind};

fn find_password(hash: Vec<u8>) -> Result<String> {
    let chars = "abcdefghijklmnopqrstuvwxyz0123456789".as_bytes();
    let chars = Vec::from(chars);

    let perms = iproduct!(&chars, &chars, &chars, &chars, &chars, &chars);

    for p in perms {
        let v = Vec::from([*p.0, *p.1, *p.2, *p.3, *p.4, *p.5]);
        let h = Vec::from(md5::compute(&v).as_slice());
        if h == hash {
            return Ok(String::from_utf8(v).expect("Unexpected failure!"));
        }
    }

    Err(ReadlineError::Io(Error::new(
        ErrorKind::NotFound,
        "Password has not been found!",
    )))
}

fn check_len(mut line: String, n: usize) -> Result<String> {
    let l = line.len();
    if l > n {
        println!("The input is too long, so it was cut to the appropriate size!");
        line.drain(n..);
        println!("Now the input is: {:?}", line);
    } else if l < n {
        return Err(ReadlineError::Io(Error::new(
            ErrorKind::InvalidInput,
            "There are not enough symbols",
        )));
    }

    Ok(line)
}

fn check_line(mut line: String, sem: u8) -> Result<Vec<u8>> {
    line = String::from(line.to_lowercase().trim());
    match sem {
        b'p' => {
            line = check_len(line, 6)?;
        }
        b'h' => {
            line = check_len(line, 32)?;
        }
        _ => return Err(ReadlineError::Eof),
    }

    for c in line.as_bytes().iter() {
        if !c.is_ascii_alphanumeric() {
            return Err(ReadlineError::Io(Error::new(ErrorKind::InvalidInput, "String contains invalid passwod/has-sum characters.")));
        }
    }

    Ok(Vec::from(line))
}

fn parse_hash(s: Vec<u8>) -> Result<Vec<u8>> {
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
            Err(_) => {
                return Err(ReadlineError::Io(Error::new(
                    ErrorKind::InvalidInput,
                    "Failed to parse hash-sum!",
                )));
            }
        };
    }

    Ok(Vec::from(hash))
}

fn main() -> Result<()> {
    println!("Following options are avaluable:");
    println!(":q -- quit");
    println!(":p -- input password");
    println!(":h -- input hash-sum");
    println!(":t -- run tests");
    let mut rl = DefaultEditor::new()?;
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => match line.trim() {
                ":p" => {
                    println!("Input 6 symbol password. Allowed symbols are: a-z, 0-9");
                    let password = rl.readline(">> ")?;
                    let password = match check_line(password, b'p') {
                        Ok(v) => v,
                        Err(err) => {
                            println!("Error: {}", err);
                            continue;
                        }
                    };
                    let digest = md5::compute(password);
                    println!("Hash-sum for the password is: {:?}", digest);
                }
                ":h" => {
                    println!("Input 32 symbols of hash-sum:");
                    let hash = rl.readline(">> ")?;
                    let hash = match check_line(hash, b'h') {
                        Ok(v) => v,
                        Err(err) => {
                            println!("Error: {}", err);
                            continue;
                        }
                    };
                    let pswd = find_password(parse_hash(hash)?)?;
                    println!("The found password is: {:?}", pswd);
                }
                ":q" => {
                    println!("Quit!");
                    break;
                }

                ":t" => {
                    // pswd = aaaaaa, hash = 0b4e7a0e5fe84ad35fb5f95b9ceeac79
                    assert_eq!(
                        "aaaaaa",
                        find_password(parse_hash(Vec::from("0b4e7a0e5fe84ad35fb5f95b9ceeac79"))?)?
                    );
                    println!("Test 1 passed");
                    // pswd = aaaaab, hash = 9dcf6acc37500e699f572645df6e87fc
                    assert_eq!(
                        "aaaaab",
                        find_password(parse_hash(Vec::from("9dcf6acc37500e699f572645df6e87fc"))?)?
                    );
                    println!("Test 2 passed");
                    // pswd = adsfgh, hash = 0789b689641c2c90aee68af7bc0ae403
                    assert_eq!(
                        "adsfgh",
                        find_password(parse_hash(Vec::from("0789b689641c2c90aee68af7bc0ae403"))?)?
                    );
                    println!("Test 3 passed");
                    // pswd = ads7gh, hash = 6a53ad86f592a1920ac2cad1b72227b4
                    assert_eq!(
                        "ads7gh",
                        find_password(parse_hash(Vec::from("6a53ad86f592a1920ac2cad1b72227b4"))?)?
                    );
                    println!("Test 4 passed");
                    // pswd = 4a5b6c, hash = 021e26cd1924f3172b911de75c643e0f
                    // pswd = 123456, hash = e10adc3949ba59abbe56e057f20f883e
                    assert_eq!(
                        "123456",
                        find_password(parse_hash(Vec::from("e10adc3949ba59abbe56e057f20f883e"))?)?
                    );
                    println!("Test 5 passed");
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
