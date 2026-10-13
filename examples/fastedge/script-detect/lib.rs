//! A script detector: POST text, get back a JSON array of the scripts its
//! letters use, each narrowed to the European alphabets its letters fit.
//!
//!     $ curl --data 'Grüße aus Köln' http://localhost:8080/
//!     ["German"]
//!
//! It looks at LETTERS only, never at words. All the matching is done by the
//! regexp component compiled from regexped.yaml; this file only decides which
//! sets to ask and turns pattern ids into names.

use wstd::http::body::Body;
use wstd::http::{Method, Request, Response, StatusCode};

include!("stubs.rs");

use scriptdetect::{
    cyrillic_languages, cyrillic_pattern_name, find_scripts, latin_languages, latin_pattern_name,
    scripts_pattern_name,
};

#[wstd::http_server]
async fn main(mut request: Request<Body>) -> anyhow::Result<Response<Body>> {
    if request.method() != Method::POST {
        return reply(StatusCode::METHOD_NOT_ALLOWED, "POST the text to detect\n".into());
    }
    let text = request.body_mut().contents().await?;
    if std::str::from_utf8(text).is_err() {
        return reply(StatusCode::BAD_REQUEST, "the body must be UTF-8 text\n".into());
    }
    let found = detect(text)?;
    let response = Response::builder()
        .header("content-type", "application/json")
        .body(Body::from_json(&found)?)?;
    Ok(response)
}

/// The languages the text's letters allow, script by script in the order the
/// scripts first appear. A script none of whose languages match — plain a-z
/// text, Cyrillic using only the letters its languages share, any Greek — is
/// reported by its own name.
fn detect(text: &[u8]) -> scriptdetect::Result<Vec<&'static str>> {
    let mut scripts: Vec<i32> = Vec::new();
    for m in find_scripts(text, 0) {
        let id = m?.pattern_id;
        if !scripts.contains(&id) {
            scripts.push(id);
        }
    }
    let mut found = Vec::new();
    for script in scripts {
        // Each set names its own ids: a set's lookup knows only its members.
        let name = scripts_pattern_name(script);
        let languages: Vec<&'static str> = match name {
            "Latin" => latin_languages(text)?.map(latin_pattern_name).collect(),
            "Cyrillic" => cyrillic_languages(text)?.map(cyrillic_pattern_name).collect(),
            _ => Vec::new(),
        };
        if languages.is_empty() {
            found.push(name);
        } else {
            found.extend(languages);
        }
    }
    Ok(found)
}

fn reply(status: StatusCode, message: String) -> anyhow::Result<Response<Body>> {
    Ok(Response::builder().status(status).body(message.into())?)
}
