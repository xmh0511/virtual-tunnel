use super::config::Log;
use time::{macros::format_description, UtcOffset};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::time::OffsetTime;

pub fn set_log(config:Log)->Option<WorkerGuard>{
	let local_time = OffsetTime::new(
        UtcOffset::from_hms(config.utcoffset[0], config.utcoffset[1], config.utcoffset[2]).unwrap(),
        format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"),
    );
	if !cfg!(debug_assertions){
		let file_appender = tracing_appender::rolling::hourly(&config.dir, &config.prefix);
		let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
		tracing_subscriber::fmt().with_timer(local_time).with_max_level(tracing::Level::INFO).with_writer(non_blocking).init();
		Some(guard)
	}else{
		tracing_subscriber::fmt().with_timer(local_time).init();
		None
	}
}