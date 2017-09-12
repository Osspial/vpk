extern crate vpk;

use std::fs::File;
use std::io::BufReader;

use vpk::DirReader;

fn main() {
    let file = File::open("D:/steam/steamapps/common/team fortress 2/tf/custom/ABS_MRP_Improved_FGD.vpk").unwrap();
    let mut reader = DirReader::new(BufReader::new(file)).unwrap();
    for entry in reader {
        print!("{:#?}\n", entry.unwrap());
    }
    println!();
}
