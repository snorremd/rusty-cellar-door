extern crate actix_web;
extern crate bcrypt;
extern crate chrono;
extern crate env_logger;
extern crate jsonwebtoken as jwt;
extern crate listenfd;
extern crate lru_time_cache;
extern crate uuid;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_urlencoded;

#[macro_use]
extern crate tera;

#[macro_use]
extern crate log;

mod app;
mod auth;
mod index;
mod login;
mod token;

use actix_web::server;
use listenfd::ListenFd;

fn main() {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();
    let mut listenfd = ListenFd::from_env();

    let cache = app::cache();
    let mut server = server::new(move || app::new_app(cache.clone()));

    server = if let Some(l) = listenfd.take_tcp_listener(0).unwrap() {
        server.listen(l)
    } else {
        server.bind("127.0.0.1:3000").unwrap()
    };

    server.run();
}
