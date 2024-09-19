use rustyline::error::ReadlineError;
use rustyline::{DefaultEditor, Result};
use itertools::Itertools;

fn find_password(hash:&[u8]) -> Vec<u8> {
    let chars = "abcdefghijklmnopqrstuvwxyz0123456789".as_bytes();
    let chars = Vec::from(chars);

    let perms = chars.into_iter().permutations(6);

    let mut pswd = Vec::new();
    for v in perms {
        if md5::compute(&v).as_slice() == hash {
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
                    },
                    ":h" => {
                        println!("Input 8 symbols with digits 4 times:");
                        let mut hash = rl.readline("A = 0x")?;
                        let B = rl.readline("B = 0x")?;
                        let C = rl.readline("C = 0x")?;
                        let D = rl.readline("D = 0x")?;
                        hash.push_str(B.as_str());
                        hash.push_str(C.as_str());
                        hash.push_str(D.as_str());
                        println!("Hash-sum now is {hash}");
                        let pswd = find_password(hash.as_bytes());
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