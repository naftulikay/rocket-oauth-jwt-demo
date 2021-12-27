use rocket::fs::NamedFile;
use rocket::{get, routes, Build, Rocket};
use rocket_dyn_templates::Template;
use std::path::{Path, PathBuf};

#[get("/")]
fn index() -> Template {
    Template::render("index", serde_json::Value::Object(Default::default()))
}

#[get("/static/<file..>")]
async fn static_files(file: PathBuf) -> Option<NamedFile> {
    NamedFile::open(Path::new("static/").join(file)).await.ok()
}

pub fn start() -> Rocket<Build> {
    rocket::build()
        .mount("/", routes![index, static_files])
        .attach(Template::fairing())
}
