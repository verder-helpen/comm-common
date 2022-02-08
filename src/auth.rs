use std::{convert::TryFrom, str::FromStr};

use crate::config::Config;
use crate::error::Error;
use crate::templates::{RenderType, RenderedContent, Translations, TEMPLATES, TRANSLATIONS};

use reqwest::header::AUTHORIZATION;
use rocket::{
    fairing::{AdHoc, Fairing},
    http::{Cookie, CookieJar, SameSite},
    outcome::IntoOutcome,
    request::{self, FromRequest, Request},
    response::Redirect,
    State,
};
use rocket_oauth2::{OAuth2, TokenResponse};
use serde::{Deserialize, Serialize};
use tera::Context;

#[derive(Deserialize, Serialize)]
pub struct LoginUrl {
    pub login_url: String,
}

#[derive(Debug, strum_macros::EnumString)]
pub enum AuthProvider {
    Google,
    Microsoft,
}

impl AuthProvider {
    pub fn fairing(&self) -> impl Fairing {
        match self {
            AuthProvider::Google => AdHoc::on_ignite("Auth", |rocket| async {
                rocket
                    .mount(
                        "/",
                        rocket::routes![login_google, redirect_google, logout_generic,],
                    )
                    .attach(OAuth2::<Google>::fairing("google"))
            }),
            AuthProvider::Microsoft => AdHoc::on_ignite("Auth", |rocket| async {
                rocket
                    .mount(
                        "/",
                        rocket::routes![login_microsoft, redirect_microsoft, logout_generic,],
                    )
                    .attach(OAuth2::<Microsoft>::fairing("microsoft"))
            }),
        }
    }
}

impl TryFrom<String> for AuthProvider {
    type Error = Error;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        Ok(AuthProvider::from_str(&name)?)
    }
}

pub struct TokenCookie(String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for TokenCookie {
    type Error = Error;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<TokenCookie, Error> {
        request
            .cookies()
            .get_private("token")
            .and_then(|c| c.value().parse().ok())
            .map(TokenCookie)
            .or_forward(())
    }
}

struct Google;

#[rocket::get("/auth/login")]
fn login_google(cookies: &CookieJar<'_>, oauth2: OAuth2<Google>) -> Redirect {
    oauth2.get_redirect(cookies, &["profile"]).unwrap()
}

#[rocket::get("/auth/redirect")]
async fn redirect_google(
    config: &State<Config>,
    cookies: &CookieJar<'_>,
    token: TokenResponse<Google>,
) -> Result<String, Error> {
    redirect_generic(config, cookies, token).await
}

#[derive(serde::Deserialize)]
struct GoogleUserInfo {
    #[serde(default)]
    sub: String,
}

// Currently only checks whether we can actually login with the provided cookie
async fn check_token_google(token: TokenCookie) -> Result<bool, Error> {
    let user_info: GoogleUserInfo = reqwest::Client::builder()
        .build()?
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .header(AUTHORIZATION, format!("Bearer {}", token.0))
        .send()
        .await?
        .json()
        .await?;

    Ok(!user_info.sub.is_empty())
}

struct Microsoft;

#[rocket::get("/auth/login")]
fn login_microsoft(cookies: &CookieJar<'_>, oauth2: OAuth2<Microsoft>) -> Redirect {
    oauth2.get_redirect(cookies, &["user.read"]).unwrap()
}

#[rocket::get("/auth/redirect")]
async fn redirect_microsoft(
    config: &State<Config>,
    cookies: &CookieJar<'_>,
    token: TokenResponse<Microsoft>,
) -> Result<String, Error> {
    redirect_generic(config, cookies, token).await
}

#[derive(serde::Deserialize)]
struct MicrosoftUserInfo {
    #[serde(default, rename = "displayName")]
    display_name: String,
}

// Currently only checks whether we can actually login with the provided cookie
async fn check_token_microsoft(token: TokenCookie) -> Result<bool, Error> {
    let user_info: MicrosoftUserInfo = reqwest::Client::builder()
        .build()?
        .get("https://graph.microsoft.com/v1.0/me")
        .header(AUTHORIZATION, format!("Bearer {}", token.0))
        .send()
        .await?
        .json()
        .await?;

    Ok(!user_info.display_name.is_empty())
}

pub async fn check_token(token: TokenCookie, config: &Config) -> Result<bool, Error> {
    match config.auth_provider() {
        Some(AuthProvider::Google) => check_token_google(token).await,
        Some(AuthProvider::Microsoft) => check_token_microsoft(token).await,
        None => Err(Error::Forbidden("No auth provider configured".to_owned())),
    }
}

async fn redirect_generic<T>(
    config: &State<Config>,
    cookies: &CookieJar<'_>,
    token: TokenResponse<T>,
) -> Result<String, Error> {
    if check_token(TokenCookie(token.access_token().to_owned()), config).await? {
        cookies.add_private(
            Cookie::build("token", token.access_token().to_owned())
                .http_only(true)
                .secure(true)
                .same_site(SameSite::Lax)
                .finish(),
        );

        return Ok(TRANSLATIONS.get(
            "login_successful",
            "You are now logged in. You can close this window",
        ));
    }

    Err(Error::Forbidden(TRANSLATIONS.get(
        "insufficient_permissions",
        "Insufficient permissions, try logging in with another account",
    )))
}

#[rocket::post("/auth/logout")]
async fn logout_generic(cookies: &CookieJar<'_>) -> Result<String, Error> {
    cookies.remove_private(Cookie::named("token"));
    Ok(TRANSLATIONS.get(
        "logout_successful",
        "You are now logged out. You can close this window",
    ))
}

pub fn render_login(config: &Config, render_type: RenderType) -> Result<RenderedContent, Error> {
    let login_url = format!("{}/auth/login", config.external_url());
    if render_type == RenderType::Html {
        let mut context = Context::new();
        let translations: Translations = TRANSLATIONS.clone();

        context.insert("translations", &translations);
        context.insert("login_url", &login_url);

        let content = TEMPLATES.render("login.html", &context)?;
        return Ok(RenderedContent {
            content,
            render_type,
        });
    }

    Err(Error::Unauthorized(login_url))
}

pub fn render_unauthorized(
    config: &Config,
    render_type: RenderType,
) -> Result<RenderedContent, Error> {
    let logout_url = format!("{}/auth/logout", config.external_url());
    if render_type == RenderType::Html {
        let mut context = Context::new();
        let translations: Translations = TRANSLATIONS.clone();

        context.insert("translations", &translations);
        context.insert("logout_url", &logout_url);

        let content = TEMPLATES.render("expired.html", &context)?;
        return Ok(RenderedContent {
            content,
            render_type,
        });
    }

    Err(Error::Forbidden(logout_url))
}