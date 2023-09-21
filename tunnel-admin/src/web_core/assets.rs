use salvo::prelude::*;
#[allow(dead_code)]
pub fn common_assets(pub_dir:String,listing:bool)->Router{
    Router::with_path("public/<**path>").get(
        StaticDir::new([
			pub_dir
        ])
        .defaults("index.html")
        .listing(listing),
    )
}