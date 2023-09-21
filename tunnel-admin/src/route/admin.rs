use crate::web_core::{
    config::Config,
    error_catch::{AnyResult, HttpErrorKind, Option2AnyHttpResult, Result2AnyHttpResult},
};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io;

use crate::web_core::authorization::gen_token;
use config_file::{ConfigFileError, FromConfigFile};

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaim {
    username: String,
    exp: i64,
}

#[derive(Deserialize, Serialize)]
struct Host {
    identifier: String,
    vir: String,
}

#[derive(Deserialize, Serialize, Default)]
struct NodeConfig {
    host: Vec<Host>,
}

async fn save_vec_to_file(v: Vec<Host>) -> io::Result<()> {
    let r: Vec<String> = v
        .iter()
        .map(|item| {
            format!(
                "[[host]]\r\nidentifier = \"{}\"\r\nvir = \"{}\"",
                item.identifier, item.vir
            )
        })
        .collect();
    let r = r.join("\r\n\r\n");
    tokio::fs::write("./node.toml", r).await
}

#[handler]
pub async fn list(_req: &mut Request, res: &mut Response) -> AnyResult<()> {
    let config = match NodeConfig::from_config_file("./node.toml") {
        Ok(v) => v,
        Err(ConfigFileError::FileAccess(e)) =>{
			res.render(Text::Json(
                json!({
                    "status":"fail",
                    "msg": e.to_string()
                })
                .to_string(),
            ));
            return Ok(());
		}
        Err(_) => {
			NodeConfig::default()
        }
    };

    let node_list = config.host;
    let r = json!({
        "status":"success",
        "msg":{
            "list":node_list
        }
    });

    res.render(Text::Json(r.to_string()));
    Ok(())
}

#[handler]
pub async fn del(req: &mut Request, res: &mut Response) -> AnyResult<()> {
    let ident = req.form::<String>("id").await.to_result(|| {
        (
            400,
            HttpErrorKind::Json(json!({
                "status":"fail",
                "msg":"id is required"
            })),
        )
    })?;
    let config = match NodeConfig::from_config_file("./node.toml") {
        Ok(v) => v,
        Err(ConfigFileError::FileAccess(e)) =>{
			res.render(Text::Json(
                json!({
                    "status":"fail",
                    "msg": e.to_string()
                })
                .to_string(),
            ));
            return Ok(());
		}
        Err(_) => {
			NodeConfig::default()
        }
    };
    let mut node_list = config.host;

    let index = node_list
        .iter()
        .position(|e| e.identifier == ident)
        .to_result(|| {
            (
                400,
                HttpErrorKind::Json(json!({
                    "status":"fail",
                    "msg":"id is invalid"
                })),
            )
        })?;

    node_list.remove(index);

    save_vec_to_file(node_list).await.to_result(|_| {
        (
            400,
            HttpErrorKind::Json(json!({
                "status":"fail",
                "msg":"an error occurs while saving the file"
            })),
        )
    })?;
    res.render(Text::Json(
        json!({
            "status":"success",
            "msg":"delete OK"
        })
        .to_string(),
    ));
    Ok(())
}

#[handler]
pub async fn add(req: &mut Request, res: &mut Response) -> AnyResult<()> {
    let vir = req.form::<String>("vir").await.to_result(|| {
        (
            400,
            HttpErrorKind::Json(json!({
                "status":"fail",
                "msg":"vir is required"
            })),
        )
    })?;
    let config = match NodeConfig::from_config_file("./node.toml") {
        Ok(v) => v,
        Err(ConfigFileError::FileAccess(e)) =>{
			res.render(Text::Json(
                json!({
                    "status":"fail",
                    "msg": e.to_string()
                })
                .to_string(),
            ));
            return Ok(());
		}
        Err(_) => {
			NodeConfig::default()
        }
    };
    let mut node_list = config.host;

    if node_list.iter().find(|item| item.vir == vir).is_some() {
        res.render(Text::Json(
            json!({
                "status":"fail",
                "msg":"the set virtual address has already been allocated"
            })
            .to_string(),
        ));
        return Ok(());
    }

    node_list.push(Host {
        identifier: format!("{:x}", md5::compute(uuid::Uuid::new_v4())),
        vir: vir,
    });
    save_vec_to_file(node_list).await.to_result(|_| {
        (
            400,
            HttpErrorKind::Json(json!({
                "status":"fail",
                "msg":"an error occurs while saving the file"
            })),
        )
    })?;

    res.render(Text::Json(
        json!({
            "status":"success",
            "msg":"add OK"
        })
        .to_string(),
    ));
    Ok(())
}

#[handler]
pub async fn login(req: &mut Request, depot: &mut Depot, res: &mut Response) -> AnyResult<()> {
    let config = depot.obtain::<Config>().to_result(|_| {
        (
            400,
            HttpErrorKind::Json(json!({
                "status":"fail",
                "msg":"config not found"
            })),
        )
    })?;
    let user = req.form::<String>("user").await.to_result(|| {
        (
            400,
            HttpErrorKind::Json(json!({
                "status":"fail",
                "msg":"user is required"
            })),
        )
    })?;
    let pass = req.form::<String>("pass").await.to_result(|| {
        (
            400,
            HttpErrorKind::Json(json!({
                "status":"fail",
                "msg":"user is required"
            })),
        )
    })?;
    //println!("{config:?}, {user:?}, {pass:?}");
    if user != config.admin.user || pass != config.admin.pass {
        res.render(Text::Json(
            json!({
                "status":"fail",
                "msg":"user or pass is not valid"
            })
            .to_string(),
        ));
        return Ok(());
    }
    let token = gen_token(
        config.secret_key.clone(),
        JwtClaim {
            exp: crate::expire_time!(Days(1)),
            username: user,
        },
    )
    .to_result(|e| {
        (
            400,
            HttpErrorKind::Json(json!({
                "status":"fail",
                "msg":e
            })),
        )
    })?;
    res.render(Text::Json(
        json!({
            "status":"success",
            "msg":{
                "token":token
            }
        })
        .to_string(),
    ));
    Ok(())
}
