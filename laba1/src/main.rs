use itertools::iproduct;
use rustyline::error::ReadlineError;
use rustyline::{DefaultEditor, Result};

fn find_password(hash: Vec<u8>) -> String {
    let chars = "abcdefghijklmnopqrstuvwxyz0123456789".as_bytes();
    let chars = Vec::from(chars);

    let perms = iproduct!(&chars, &chars, &chars, &chars, &chars, &chars);

    for p in perms {
        let v = Vec::from([*p.0, *p.1, *p.2, *p.3, *p.4, *p.5]);
        let h = Vec::from(md5::compute(&v).as_slice());
        if h == hash {
            return String::from_utf8(v).expect("Failed while converting found password!");
        }
    }

    String::new()
}

fn check_len(mut line: String, n: usize) -> Result<String> {
    let l = line.len();
    if l > n {
        println!("The input is too long, so it was cut to the appropriate size!");
        line.drain(n..);
        println!("Now the input is: {:?}", line);
    } else if l < n {
        println!("Error: There are not enough symbols.");
        return Err(ReadlineError::Eof);
    }

    Ok(line)
}

fn check_line(mut line: String, sem: u8) -> Result<Vec<u8>> {
    line = line.to_lowercase();
    match sem {
        b'p' => {
            line = check_len(line, 6)?;
            Ok(Vec::from(line))
        }
        b'h' => {
            line = check_len(line, 32)?;
            Ok(Vec::from(line))
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
    println!(":t - run tests");
    let mut rl = DefaultEditor::new()?;
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => match &line.trim()[..] {
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

                ":t" => {
                    // pswd = aaaaaa, hash = 0b4e7a0e5fe84ad35fb5f95b9ceeac79
                    assert_eq!(
                        "aaaaaa",
                        find_password(Vec::from(b"0b4e7a0e5fe84ad35fb5f95b9ceeac79"))
                    );
                    // pswd = aaaaab, hash = 9dcf6acc37500e699f572645df6e87fc
                    // pswd = adsfgh, hash = 0789b689641c2c90aee68af7bc0ae403
                    // pswd = ads7gh, hash = 6a53ad86f592a1920ac2cad1b72227b4
                    // pswd = 4a5b6c, hash = 021e26cd1924f3172b911de75c643e0f
                    // pswd = 123456, hash = 00c66aaf5f2c3f49946f15c1ad2ea0d3
                    // std::assert_eq!("aaaaaa");
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
