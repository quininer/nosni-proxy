use std::fs;
use std::error::Error;
use std::path::Path;


fn main() -> Result<(), Box<Error>> {
    let target = Path::new("public_suffix_list.dat");

    if !target.is_file() {
        let mut resp = reqwest::get(publicsuffix::LIST_URL)?
            .error_for_status()?;
        resp.copy_to(&mut fs::File::create(target)?)?;
    }

    print!("cargo:rerun-if-changed=public_suffix_list.dat");

    Ok(())
}
