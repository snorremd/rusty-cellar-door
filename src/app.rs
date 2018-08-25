use actix_web::middleware::session::{CookieSessionBackend, SessionStorage};
use actix_web::middleware::Logger;
use actix_web::{fs, http, App};
use auth::{auth_get, auth_post};
use index::index_get;
use login::{login_get, login_post};
use lru_time_cache::LruCache;
use std::sync::{Arc, Mutex};
use tera;
use token::{token_get, token_post};

#[derive(Debug)]
pub struct CodeItem {
    pub redirect_uri: String,
    pub client_id: String,
    pub me: String,
    pub scope: Option<String>,
}

pub struct AppState {
    pub template: tera::Tera,
    pub cache: Arc<Mutex<LruCache<String, CodeItem>>>,
}

pub fn cache() -> Arc<Mutex<LruCache<String, CodeItem>>> {
    let time_to_live = ::std::time::Duration::from_secs(3600 * 3);

    Arc::new(Mutex::new(
        LruCache::<String, CodeItem>::with_expiry_duration(time_to_live),
    ))
}

pub fn new_app(cache: Arc<Mutex<LruCache<String, CodeItem>>>) -> App<AppState> {
    // Create tera instance to handle template rendering
    let tera = compile_templates!(concat!(env!("CARGO_MANIFEST_DIR"), "/templates/**/*"));
    // Create Cookie Session Backend for login session handling
    let cookie_backend = CookieSessionBackend::private(
        "This is a super long key that is what it is".as_bytes(),
    ).domain("localhost")
        .name("rustycellardoor")
        .path("/")
        .secure(false);

    // TODO: Pass in from main.rs to share it between threads!

    let state = AppState {
        template: tera,
        cache: cache,
    };

    App::with_state(state)
        .middleware(Logger::default())
        .middleware(SessionStorage::new(cookie_backend))
        .resource("/", |r| r.method(http::Method::GET).with(index_get))
        .resource("/login", |r| {
            r.name("login");
            r.method(http::Method::GET).with(login_get);
            r.method(http::Method::POST).with(login_post)
        })
        .resource("/auth", |r| {
            r.name("auth");
            r.method(http::Method::GET).with(auth_get);
            r.method(http::Method::POST).with(auth_post)
        })
        .resource("/token", |r| {
            r.name("token");
            r.method(http::Method::GET).with(token_get);
            r.method(http::Method::POST).with(token_post)
        })
        .handler(
            "/static",
            fs::StaticFiles::new("./static")
                .unwrap()
                .show_files_listing(),
        )
}
