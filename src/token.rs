use actix_web::http::{header, StatusCode};
use actix_web::{error, Error, Form, HttpRequest, HttpResponse, State};
use app::{AppState, CodeItem};
use chrono::Utc;
use jwt::{decode, encode, Header, Validation};

#[derive(Deserialize, Debug)]
pub struct CodeAuth {
    code: String,
    redirect_uri: String,
    client_id: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    access_token: String,
    scope: String,
    me: String,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    aud: String,
    exp: i64,
    scope: String,
    sub: String,
}

fn parse_auth(request: &HttpRequest<AppState>) -> Result<String, Error> {
    let header = request
        .headers()
        .get(header::AUTHORIZATION)
        .ok_or(error::ErrorBadRequest(format!(
            "Authorization header not provided"
        )))?;

    if header.len() < 8 {
        return Err(error::ErrorBadRequest(
            "Invalid value in Authorization header",
        ));
    };

    let mut header_parts = match header.to_str() {
        Ok(val) => val.splitn(2, ' '),
        Err(err) => {
            return Err(error::ErrorBadRequest(format!(
                "Invalid value in Authorization header: {}",
                err
            )))
        }
    };

    match header_parts.next() {
        Some(scheme) if scheme == "Bearer" => (),
        _ => {
            return Err(error::ErrorBadRequest(
                "Missing scheme 'Bearer' in authorization header",
            ))
        }
    };

    let token = match header_parts.next() {
        Some(token) => token,
        None => {
            return Err(error::ErrorBadRequest(format!(
                "Failed to parse token value"
            )))
        }
    };

    Ok(token.to_string())
}

fn verify_code(state: &State<AppState>, params: &Form<CodeAuth>) -> Result<CodeItem, Error> {
    info!("Get lock on cache store for codes");
    let mut cache = match state.cache.lock() {
        Ok(cache) => cache,
        Err(error) => {
            return Err(error::ErrorInternalServerError(format!(
                "Failed to get lock on cache: {}",
                error
            )))
        }
    };

    info!("Find code in cache");
    let item = match cache.get(&params.code) {
        Some(item) => item,
        None => return Err(error::ErrorForbidden("Code is no longer valid")),
    };

    info!("Check if parameters match parameters from cached code");
    if item.client_id != params.client_id || item.redirect_uri != params.redirect_uri {
        return Err(error::ErrorForbidden(
            "Invalid code, redirect_uri, or client_id supplied",
        ));
    };

    Ok(CodeItem {
        client_id: item.client_id.clone(),
        me: item.me.clone(),
        redirect_uri: item.redirect_uri.clone(),
        scope: item.scope.clone(),
    })
}

fn create_token(item: &CodeItem) -> Result<String, Error> {
    let claims = Claims {
        aud: item.client_id.clone(),
        exp: Utc::now().timestamp() + 10000,
        scope: item.scope.clone().unwrap_or("".to_string()),
        sub: item.me.clone(),
    };

    info!("Sign an access token");
    match encode(&Header::default(), &claims, "secret".as_ref()) {
        Ok(token) => Ok(token),
        Err(error) => Err(error::ErrorInternalServerError(format!(
            "Could not sign token, {}",
            error
        ))),
    }
}

pub fn token_get(request: HttpRequest<AppState>) -> Result<HttpResponse, Error> {
    info!("Parse authorization header");
    let jwt = parse_auth(&request)?;

    info!("Decode jwt to validate token request");
    match decode::<Claims>(&jwt, "secret".as_ref(), &Validation::default()) {
        Ok(token) => token,
        Err(err) => return Err(error::ErrorForbidden(format!("Invalid token: {}", err))),
    };

    info!("Prepare response");
    Ok(HttpResponse::Ok().status(StatusCode::OK).finish())
}

pub fn token_post(
    (state, params): (State<AppState>, Form<CodeAuth>),
) -> Result<HttpResponse, Error> {
    let item = verify_code(&state, &params)?;
    let token = create_token(&item)?;

    let response = TokenResponse {
        me: item.me,
        scope: item.scope.unwrap_or(String::from("")),
        access_token: token,
    };

    info!("Create token response");
    Ok(HttpResponse::Ok().json(response))
}
