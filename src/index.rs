use actix_web::middleware::session::RequestSession;
use actix_web::{error, Error, HttpRequest, HttpResponse, State};
use app::AppState;
use tera;

pub fn index_get(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> Result<HttpResponse, Error> {
    let mut ctx = tera::Context::new();

    if let Ok(Some(session)) = req.session().get::<String>("sid-indieauth") {
        info!("Session: {}", session);
        ctx.insert("username", &session);
    }

    Ok(HttpResponse::Ok().content_type("text/html").body(state
        .template
        .render("index.html", &ctx)
        .map_err(|_| error::ErrorInternalServerError("Template error"))?))
}
