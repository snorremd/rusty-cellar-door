use actix_web::http::header;
use actix_web::http::StatusCode;
use actix_web::middleware::session::RequestSession;
use actix_web::{error, Error, Form, HttpRequest, HttpResponse, Query, State};
use app::AppState;
use bcrypt;
use tera;

#[derive(Deserialize)]
pub struct LoginFormParams {
    username: String,
    password: String,
    redirect: String,
}

#[derive(Deserialize)]
pub struct LoginQuery {
    redirect: Option<String>,
}

pub fn login_post(
    (req, params): (HttpRequest<AppState>, Form<LoginFormParams>),
) -> Result<HttpResponse, Error> {
    let mut ctx = tera::Context::new();
    let hash = "$2b$10$Nc3tg12zOz2QYWMb5L11iuImBVJOxgI4pzEQ.CcUgI0MhVomaHhh."; // supernintendo chalmers

    let valid_user = String::from("myuser").eq(&params.username);
    let valid_pass = bcrypt::verify(&params.password, hash).unwrap_or(false);

    if valid_user && valid_pass {
        info!("Valid user '{}' and password '******'", params.username);
        req.session().set("sid-indieauth", &params.username)?;

        Ok(HttpResponse::Ok()
            .header(header::LOCATION, params.redirect.clone())
            .status(StatusCode::FOUND)
            .finish())
    } else {
        info!("Invalid user '{}' or password '******'", params.username);
        ctx.add("error", "Wrong username or password!");
        ctx.add("redirect", &params.redirect);
        Ok(HttpResponse::Ok()
            .content_type("text/html")
            .body(req.state()
                .template
                .render("login.html", &ctx)
                .map_err(|_| error::ErrorInternalServerError("Template error"))?))
    }
}

pub fn login_get(
    (state, query): (State<AppState>, Query<LoginQuery>),
) -> Result<HttpResponse, Error> {
    let mut ctx = tera::Context::new();

    if let Some(redirect) = &query.redirect {
        ctx.add("redirect", &redirect);
    } else {
        ctx.add("redirect", "/");
    }

    Ok(HttpResponse::Ok().content_type("text/html").body(state
        .template
        .render("login.html", &ctx)
        .map_err(|_| error::ErrorInternalServerError("Template error"))?))
}
