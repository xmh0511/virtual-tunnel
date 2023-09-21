use salvo::prelude::*;
use serde::Deserialize;
#[cfg(feature = "http3")]
use std::path::PathBuf;
#[cfg(feature = "http3")]
use tokio::fs;

#[derive(Deserialize, Clone,Debug)]
pub struct Log {
    pub dir: String,
    pub prefix: String,
    pub utcoffset: [i8; 3],
}
#[derive(Deserialize, Clone,Debug)]
pub struct Http3 {
    pub dir: String,
    pub cert_file_name: String,
    pub key_file_name: String,
}
#[derive(Deserialize, Clone,Debug)]
pub struct Config {
    pub host: String,
    pub pub_dir: String,
    pub log: Log,
    pub db_protocol: String,
    pub route_root: String,
    pub secret_key: String,
    #[cfg(feature = "http3")]
    pub http3: Http3,
	pub admin:Admin
}

#[derive(Deserialize, Clone,Debug)]
pub struct Admin{
	pub user:String,
	pub pass:String
}


#[cfg(feature = "http3")]
pub async fn read_cert_and_key(config: Http3) -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
    let cert_root_path = PathBuf::from(config.dir);
    let cert_path = cert_root_path.join(config.cert_file_name);
    let key_path = cert_root_path.join(config.key_file_name);
    dbg!(cert_path.clone(), key_path.clone());
    let cert = fs::read(cert_path).await?;
    let key = fs::read(key_path).await?;
    Ok((cert, key))
}

pub struct InjectConfig(pub Config);
#[handler]
impl InjectConfig {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.inject(self.0.clone());
        ctrl.call_next(req, depot, res).await;
    }
}
