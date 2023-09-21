use std::fmt::Debug;

use salvo::prelude::*;

use serde_json::Value;


pub type AnyResult<T> = Result<T,AnyHttpError>;
#[allow(dead_code)]
pub enum HttpErrorKind {
    Json(Value),
    Html(String),
}


pub struct AnyHttpError(StatusCode, HttpErrorKind);

impl AnyHttpError {
    pub fn new(code: u16, msg: HttpErrorKind) -> Self {
        Self(
            StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST),
            msg,
        )
    }
}

#[async_trait]
impl Writer for AnyHttpError {
    async fn write(mut self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        res.status_code(self.0);
        match self.1 {
            HttpErrorKind::Json(v) => res.render(Text::Json(v.to_string())),
            HttpErrorKind::Html(v) => res.render(Text::Html(v)),
        }
    }
}

pub trait Option2AnyHttpResult {
    type Output;
	fn to_result<F:FnMut()->(u16,HttpErrorKind)>(self,f:F)->Result<Self::Output, AnyHttpError>;
}
impl<T> Option2AnyHttpResult for Option<T> {
    type Output = T;
	fn to_result<F:FnMut()->(u16,HttpErrorKind)>(self,mut f:F)->Result<Self::Output, AnyHttpError>{
		match self{
			Some(v)=>Ok(v),
			None=>{
				let (code,msg) = f();
				Err(AnyHttpError::new(code,msg))
			}
		}
	}
}

pub trait Result2AnyHttpResult {
    type Output;
	fn to_result<F:FnMut(String)->(u16,HttpErrorKind)>(self,f:F)->Result<Self::Output, AnyHttpError>;
}

impl<T, U:Debug> Result2AnyHttpResult for Result<T, U> {
    type Output = T;
	fn to_result<F:FnMut(String)->(u16,HttpErrorKind)>(self,mut f:F)->Result<Self::Output, AnyHttpError>{
        match self {
            Ok(v) => Ok(v),
            Err(e) => {
				let (code,msg) = f(format!("{e:?}"));
				Err(AnyHttpError::new(code, msg))
			},
        }
	}
}

