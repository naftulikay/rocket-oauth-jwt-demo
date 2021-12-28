use rkt_oauth::start;
use rocket;
use rocket::error::Error;

#[rocket::main]
async fn main() -> Result<(), Error> {
    start().launch().await
}
