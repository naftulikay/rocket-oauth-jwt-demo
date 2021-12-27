use rkt_oauth::start;
use rocket;

#[rocket::launch]
fn rkt() -> rocket::Rocket<rocket::Build> {
    start()
}
