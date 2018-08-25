use actix_web::http::header;
use actix_web::http::StatusCode;
use actix_web::middleware::session::RequestSession;
use actix_web::{error, Error, Form, HttpRequest, HttpResponse, Query, State};
use app::{AppState, CodeItem};
use serde_urlencoded;
use tera;
use uuid::Uuid;

#[derive(Deserialize, Debug)]
#[allow(non_camel_case_types)] // To make deserializing lower case params work
enum ResponseType {
    id,
    code,
}

#[derive(Deserialize)]
pub struct Auth {
    me: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    response_type: Option<ResponseType>,
    scope: Option<String>,
}

pub fn auth_get(
    (state, query, req): (State<AppState>, Query<Auth>, HttpRequest<AppState>),
) -> Result<HttpResponse, Error> {
    if let Ok(Some(_)) = req.session().get::<String>("sid-indieauth") {
        let mut ctx = tera::Context::new();

        let auth_type = match query.response_type {
            Some(ResponseType::code) => ResponseType::code,
            Some(ResponseType::id) | None => ResponseType::id,
        };

        ctx.add("auth_type", &format!("{:?}", auth_type));
        ctx.add("client_id", &query.client_id);
        ctx.add("redirect_uri", &query.redirect_uri);
        ctx.add("state", &query.state);
        ctx.add("me", &query.me);

        if let Some(scope) = &query.scope {
            let mut scope_split = scope.split(" ");
            ctx.add("scopes", &scope_split.collect::<Vec<&str>>());
            ctx.add("scope", &query.scope);
        }

        Ok(HttpResponse::Ok()
            .content_type("text/html")
            .header("foo", "bar")
            .body(state
                .template
                .render("auth.html", &ctx)
                .map_err(|_| error::ErrorInternalServerError("Template error"))?))
    } else {
        let redirect_param = &[("redirect", req.uri().to_string())];
        let redirect = serde_urlencoded::to_string(redirect_param).unwrap_or(String::from(""));

        Ok(HttpResponse::Ok()
            .header(header::LOCATION, format!("/login?{}", redirect))
            .status(StatusCode::FOUND)
            .finish())
    }
}

pub fn auth_post(
    (state, params, req): (State<AppState>, Form<Auth>, HttpRequest<AppState>),
) -> Result<HttpResponse, Error> {
    info!("Check if session is valid");

    match req.session().get::<String>("sid-indieauth") {
        Ok(Some(session)) => session,
        Err(_) | Ok(None) => {
            error!("Could not find a valid session, redirecting to login endpoint.");
            let redirect_param = &[("redirect", req.uri().to_string())];
            let redirect = serde_urlencoded::to_string(redirect_param).unwrap_or(String::from(""));

            return Ok(HttpResponse::Ok()
                .header(header::LOCATION, format!("/login?{}", redirect))
                .status(StatusCode::FOUND)
                .finish());
        }
    };

    info!("Generate uuid value to use as code");
    let code = Uuid::new_v4().to_string();

    info!("Get lock on cache");
    let mut cache = match state.cache.lock() {
        Ok(cache) => cache,
        Err(error) => {
            error!("Could not get lock on cache");
            return Ok(HttpResponse::from_error(error::ErrorInternalServerError(
                format!("Failed to get lock on cache: {}", error),
            )));
        }
    };

    info!("Store code in cache");
    cache.insert(
        code.clone(),
        CodeItem {
            client_id: params.client_id.clone(),
            me: params.me.clone(),
            redirect_uri: params.redirect_uri.clone(),
            scope: params.scope.clone(),
        },
    );

    info!("Create redirect response");
    let auth_params = &[("state", &params.state), ("code", &code)];
    let auth_encoded = serde_urlencoded::to_string(auth_params).unwrap_or(String::from(""));
    let redirect_uri = format!("{}?{}", params.redirect_uri, auth_encoded);

    Ok(HttpResponse::Ok()
        .header(header::LOCATION, redirect_uri)
        .status(StatusCode::FOUND)
        .finish())
}
