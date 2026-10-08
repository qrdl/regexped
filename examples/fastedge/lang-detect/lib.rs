//! A script and European-language detector: POST text, get back a JSON array.
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

use langdetect::{cyrillic_languages, find_scripts, latin_languages, pattern_name};

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
fn detect(text: &[u8]) -> langdetect::Result<Vec<&'static str>> {
    let mut scripts: Vec<i32> = Vec::new();
    for m in find_scripts(text, 0) {
        let id = m?.pattern_id;
        if !scripts.contains(&id) {
            scripts.push(id);
        }
    }
    let mut found = Vec::new();
    for script in scripts {
        let languages: Vec<i32> = match pattern_name(script) {
            "Latin" => latin_languages(text)?.collect(),
            "Cyrillic" => cyrillic_languages(text)?.collect(),
            _ => Vec::new(),
        };
        if languages.is_empty() {
            found.push(pattern_name(script));
        } else {
            found.extend(languages.into_iter().map(pattern_name));
        }
    }
    Ok(found)
}

fn reply(status: StatusCode, message: String) -> anyhow::Result<Response<Body>> {
    Ok(Response::builder().status(status).body(message.into())?)
}
