
mod route;
mod web_core;


use config_file::FromConfigFile;

use web_core::{
    authorization,
    config::{Config, InjectConfig},
    db_pool, log, assets,
};

use salvo::jwt_auth::HeaderFinder;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

#[cfg(feature = "http3")]
use salvo::conn::rustls::{Keycert, RustlsConfig};

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    username: String,
    exp: i64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_config_file("./config.toml").expect("config file not found");
    let config_provider = InjectConfig(config.clone());
    let _log_guard = log::set_log(config.log);
    db_pool::init_db_if_enable(&config.db_protocol).await?;
    let jwt_auth = authorization::gen_jwt_auth::<JwtClaims>(
        config.secret_key.clone(),
        vec![Box::new(HeaderFinder::new())],
    );
    let root_router = if config.route_root.is_empty() {
        Router::new().hoop(jwt_auth).hoop(config_provider)
    } else {
        Router::with_path(config.route_root)
            .hoop(jwt_auth)
            .hoop(config_provider)
    };
    let root_router = root_router.push(route::gen_router(config.secret_key)).push(assets::common_assets(config.pub_dir, true));
    #[cfg(feature = "http3")]
    {
        let cert_and_key = web_core::config::read_cert_and_key(config.http3).await?;
        let tls_config = RustlsConfig::new(
            Keycert::new()
                .cert(cert_and_key.0.as_slice())
                .key(cert_and_key.1.as_slice()),
        );
        let listener = TcpListener::new(config.host.clone()).rustls(tls_config.clone());
        let acceptor = QuinnListener::new(tls_config, config.host)
            .join(listener)
            .bind()
            .await;
        Server::new(acceptor).serve(root_router).await;
    }
    #[cfg(not(feature = "http3"))]
    {
        let acceptor = TcpListener::new(config.host).bind().await;
        Server::new(acceptor).serve(root_router).await;
    }
    Ok(())
}
