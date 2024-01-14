use haproxy_api::Core;
use mlua::prelude::*;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use crate::modsecurity_filter::ModSecurityWAF;

mod modsecurity_filter;

#[mlua::lua_module(skip_memory_check)]
fn haproxy_modsecurity(lua: &Lua) -> LuaResult<bool> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
    tracing::info!("Plugin started");
    let core = Core::new(lua)?;
    ModSecurityWAF::attach_filter(&core, "modsecurity")?;
    Ok(true)
}
