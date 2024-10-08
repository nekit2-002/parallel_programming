use rustyline::error::ReadlineError;
use rustyline::{DefaultEditor, Result};
use std::io::{Error, ErrorKind};

// ascii digits: [48; 58)
// ascii lowercase alphabetic: [97; 122]
fn iter_bytes(mut pswd: [u8; 6], hash: [u8; 16], stop_word: &[u8; 6]) -> Result<[u8; 6]> {
    let mut i = 5;
    while pswd != *stop_word {
        if hash == md5::compute(pswd).0 {
            return Ok(pswd);
        }

        if &pswd[i..] != &stop_word[i..] {
            pswd[i] += 1;
            if pswd[i] == 58 {
                pswd[i] += 39;
            }
            i = 5;
            continue;
        }

        let mut c = 0;
        for idx in [5, 4, 3, 2, 1, 0] {
            if pswd[idx] != b'z' {
                break;
            }
            c += 1;
        }

        i -= c;
        for i2 in (i + 1)..6 {
            pswd[i2] = b'0';
        }
    }

    if hash == md5::compute(stop_word).0 {
        return Ok(pswd);
    }

    Err(ReadlineError::Io(Error::new(
        ErrorKind::NotFound,
        "Password has not been found",
    )))
}

fn find_password(hash: [u8; 16], mut buffer: [u8; 6], stop_word: &[u8; 6]) -> Result<String> {
    buffer = iter_bytes(buffer, hash, stop_word)?;

    match String::from_utf8(Vec::from(buffer)) {
        Err(_) => Err(ReadlineError::Io(Error::new(
            ErrorKind::NotFound,
            "Failed to find password!",
        ))),
        Ok(s) => Ok(s),
    }
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
            return Err(ReadlineError::Io(Error::new(
                ErrorKind::InvalidInput,
                "String contains invalid passwod/hash-sum characters.",
            )));
        }
    }

    Ok(Vec::from(line))
}

fn parse_hash(s: Vec<u8>) -> Result<[u8; 16]> {
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

    Ok(hash)
}

fn main() -> Result<()> {
    println!("Following options are avaluable:");
    println!(":q -- quit");
    println!(":p -- input password");
    println!(":h -- input hash-sum");
    println!(":ph -- input hash-sum and run parallel execution of password search");
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
                    let pswd = find_password(parse_hash(hash)?, [b'0'; 6], b"zzzzzz")?;
                    println!("The found password is: {:?}", pswd);
                }

                ":ph" => {
                    println!("Input 32 symbols of hash-sum:");
                    let hash = rl.readline(">> ")?;
                    let hash = match check_line(hash, b'h') {
                        Ok(v) => v,
                        Err(err) => {
                            println!("Error: {}", err);
                            continue;
                        }
                    };

                    let needed_hash = parse_hash(hash)?.clone();
                    std::thread::spawn(move || {
                        let tid = std::thread::current().id();
                        match find_password(needed_hash, [b'0'; 6], b"8zzzzz") {
                            Ok(pswd) => {
                                println!("Found password {} from {:?}", pswd, tid);
                            }
                            Err(err) => {
                                println!("Error: {}", err)
                            }
                        }

                        std::process::exit(0);
                    });

                    std::thread::spawn(move || {
                        let tid = std::thread::current().id();
                        match find_password(
                            needed_hash,
                            [b'9', b'0', b'0', b'0', b'0', b'0'],
                            b"hzzzzz",
                        ) {
                            Ok(pswd) => {
                                println!("Found password {} from {:?}", pswd, tid);
                            }
                            Err(err) => {
                                println!("Error: {}", err)
                            }
                        };

                        std::process::exit(0);
                    });

                    std::thread::spawn(move || {
                        let tid = std::thread::current().id();
                        match find_password(
                            needed_hash,
                            [b'i', b'0', b'0', b'0', b'0', b'0'],
                            b"qzzzzz",
                        ) {
                            Ok(pswd) => {
                                println!("Found password {} from {:?}", pswd, tid);
                            }
                            Err(err) => {
                                println!("Error: {}", err)
                            }
                        };

                        std::process::exit(0);
                    });

                    std::thread::spawn(move || {
                        let tid = std::thread::current().id();
                        match find_password(
                            needed_hash,
                            [b'r', b'0', b'0', b'0', b'0', b'0'],
                            b"zzzzzz",
                        ) {
                            Ok(pswd) => {
                                println!("Found password {} from {:?}", pswd, tid);
                            }
                            Err(err) => {
                                println!("Error: {}", err)
                            }
                        };

                        std::process::exit(0);
                    });
                }

                ":q" => {
                    println!("Quit!");
                    break;
                }

                ":t" => {
                    // pswd = aaaaaa, hash = 0b4e7a0e5fe84ad35fb5f95b9ceeac79
                    assert_eq!(
                        "aaaaaa",
                        find_password(
                            parse_hash(Vec::from("0b4e7a0e5fe84ad35fb5f95b9ceeac79"))?,
                            [b'0'; 6],
                            b"zzzzzz"
                        )?
                    );
                    println!("Test 1 passed");
                    // pswd = aaaaab, hash = 9dcf6acc37500e699f572645df6e87fc
                    assert_eq!(
                        "aaaaab",
                        find_password(
                            parse_hash(Vec::from("9dcf6acc37500e699f572645df6e87fc"))?,
                            [b'0'; 6],
                            b"zzzzzz"
                        )?
                    );
                    println!("Test 2 passed");
                    // pswd = adsfgh, hash = 0789b689641c2c90aee68af7bc0ae403
                    assert_eq!(
                        "adsfgh",
                        find_password(
                            parse_hash(Vec::from("0789b689641c2c90aee68af7bc0ae403"))?,
                            [b'0'; 6],
                            b"zzzzzz"
                        )?
                    );
                    println!("Test 3 passed");
                    // pswd = ads7gh, hash = 6a53ad86f592a1920ac2cad1b72227b4
                    assert_eq!(
                        "ads7gh",
                        find_password(
                            parse_hash(Vec::from("6a53ad86f592a1920ac2cad1b72227b4"))?,
                            [b'0'; 6],
                            b"zzzzzz"
                        )?
                    );
                    println!("Test 4 passed");
                    // pswd = 4a5b6c, hash = 021e26cd1924f3172b911de75c643e0f
                    // pswd = 123456, hash = e10adc3949ba59abbe56e057f20f883e
                    assert_eq!(
                        "123456",
                        find_password(
                            parse_hash(Vec::from("e10adc3949ba59abbe56e057f20f883e"))?,
                            [b'0'; 6],
                            b"zzzzzz"
                        )?
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
