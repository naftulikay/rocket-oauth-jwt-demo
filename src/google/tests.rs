use super::{EXPIRES_TIME_FORMAT, REGEX_GMT_TRANSPOSER};

use time::OffsetDateTime;

const EXPIRES_EXAMPLE: &'static str = "Thu, 06 Jan 2022 02:53:35 GMT";

#[test]
fn test_expires_header_parse() {
    let date = OffsetDateTime::parse(
        REGEX_GMT_TRANSPOSER
            .replace(EXPIRES_EXAMPLE, "00:00")
            .as_ref(),
        EXPIRES_TIME_FORMAT,
    )
    .unwrap();

    println!("{:?}", date);
}
