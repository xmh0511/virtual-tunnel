use sea_orm::{Database, DatabaseConnection, DbErr};
use std::sync::OnceLock;

use super::error_catch::{AnyResult, HttpErrorKind, Option2AnyHttpResult};

static DBCONN_POOL: OnceLock<DatabaseConnection> = OnceLock::new();

async fn init_db_pool(protocol: &str) -> Result<(), DbErr> {
    let _ = DBCONN_POOL.set(Database::connect(protocol).await?);
    Ok(())
}
#[allow(dead_code)]
pub fn get_db_pool<F: FnMut() -> (u16, HttpErrorKind)>(
    if_error: F,
) -> AnyResult<&'static DatabaseConnection> {
    DBCONN_POOL.get().to_result(if_error)
}

#[allow(dead_code)]
pub async fn init_db_if_enable(protocol: &str) -> Result<(), DbErr> {
    if cfg!(feature = "mysql") || cfg!(feature = "sqlite") || cfg!(feature = "postgres") {
        init_db_pool(protocol).await
    } else {
        Ok(())
    }
}
