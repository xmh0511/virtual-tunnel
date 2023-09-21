mod admin;

use salvo::Router;
use serde_json::json;

use crate::web_core::{authorization::AuthGuard, error_catch::HttpErrorKind};

use salvo::cors::{Cors, CorsHandler};
use salvo::http::Method;

use salvo::prelude::*;

#[allow(unused_macros)]
macro_rules! create_router {
	($($m:ident)::*,$($method:ident),+) => {
		//Router::with_path(acquire_last_ident!($($m)*)).$method($($m)::*)
		create_router!(IN Router::with_path(acquire_last_ident!($($m)*)), $($m)::* , $($method),+)
	};
	($prefix:literal,$($m:ident)::*,$($method:ident),+)=>{
		//Router::with_path(format!("{}{}",$prefix,acquire_last_ident!($($m)*))) $(. $method( $($m)::*  ))+
		create_router!(IN Router::with_path(format!("{}{}",$prefix,acquire_last_ident!($($m)*))), $($m)::* , $($method),+)
	};
	(IN $e:expr, $m:path , $($method:ident),+)=>{
		$e $(.$method($m))+
	};
}
#[allow(unused_macros)]
macro_rules! acquire_last_ident {
	($ide:ident $($ids:ident)+) => {
		acquire_last_ident!($($ids)+)
	};
	($ide:ident)=>{
		stringify!($ide)
	}
}

pub fn gen_router(_secret_key: String) -> Router {
    let api_router = Router::new();
    let list = create_router!(admin::list, get).hoop(AuthGuard::new(|_a| {
        HttpErrorKind::Json(json!({
            "status":"fail",
            "msg":"unauthorized"
        }))
    })).options(handler::empty());
	let del = create_router!(admin::del, post).hoop(AuthGuard::new(|_a| {
        HttpErrorKind::Json(json!({
            "status":"fail",
            "msg":"unauthorized"
        }))
    })).options(handler::empty());

	let add = create_router!(admin::add, post).hoop(AuthGuard::new(|_a| {
        HttpErrorKind::Json(json!({
            "status":"fail",
            "msg":"unauthorized"
        }))
    })).options(handler::empty());

    let login = Router::with_path("login").post(admin::login);
    api_router.push(list).push(login).push(del).push(add)
}
#[allow(dead_code)]
pub fn build_cros(allow_origin: &str) -> CorsHandler {
    Cors::new()
        .allow_origin(allow_origin)
        .allow_methods(vec![
            Method::GET,
            Method::POST,
            Method::DELETE,
            Method::PUT,
            Method::PATCH,
        ])
        .into_handler()
}
