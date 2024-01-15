use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender};
use std::time::Duration;

use glob::glob;
use haproxy_api::{Core, FilterMethod, UserFilter};
use modsecurity::{Intervention, ModSecurity, RulesSet, Transaction};
use once_cell::sync::Lazy;
use rayon::{ThreadPool, ThreadPoolBuilder};
use tracing::instrument;

type Headers = Vec<(String, Vec<String>)>;
#[derive(Default)]
pub struct ModSecurityWAF {
    current_headers: Headers,
    blocking: bool,
    intervention: Option<Intervention>,
    request_body_max_size: Option<isize>,
}

impl ModSecurityWAF {
    pub fn attach_filter(core: &Core, name: &str) -> mlua::Result<()> {
        core.register_filter::<Self>(name)?;
        Ok(())
    }
}

static POOL: Lazy<ThreadPool> = Lazy::new(|| {
    ThreadPoolBuilder::new()
        .panic_handler(|p| {
            tracing::error!(?p, "Panic in thread pool");
        })
        .build()
        .expect("Must be able to create thread")
});

static PATHS: Lazy<Vec<PathBuf>> = Lazy::new(|| {
    let rules_globs: String = std::env::var("MODSECURITY_RULE_PATHS").unwrap_or_default();
    let rules_globs = rules_globs.split(",").map(|s| glob(s));
    let mut results = vec![];
    for glob in rules_globs {
        let glob = match glob {
            Ok(glob) => glob,
            Err(error) => {
                tracing::error!(%error, "Invalid glob pattern to load modsecurity rules");
                continue;
            }
        };

        for path in glob {
            match path {
                Ok(path) => results.push(path),
                Err(error) => tracing::error!(%error, "Cannot load rules from path"),
            }
        }
    }
    results
});

thread_local! {
    static MOD_SECURITY: RefCell<(ModSecurity, RulesSet)> = RefCell::new((ModSecurity::default(), RulesSet::from_paths(&PATHS).expect("Must be able to load rules")))
}

#[derive(Debug)]
struct CheckRequestParams {
    uri: String,
    headers: Headers,
    body: Vec<u8>,
    client_ip: String,
    client_port: u16,
    server_addr: String,
    method: String,
    version: String,
    id: String,
}

#[instrument(level = "trace", skip(sender))]
fn check_request(params: CheckRequestParams, sender: Option<Sender<Intervention>>) {
    MOD_SECURITY.with_borrow_mut(|(modsec, rules)| {
        let mut tx = Transaction::new(modsec, rules, Some(&params.id));
        let _ = tx.process_connection(
            params
                .client_ip
                .parse()
                .unwrap_or("0.0.0.0".parse().unwrap()),
            params.client_port,
            &params.server_addr,
            80,
        );
        let _ = tx.process_uri(&params.uri, &params.method, &params.version);
        for (name, values) in params.headers {
            for value in values {
                let _ = tx.add_request_header(&name, &value);
            }
        }
        let _ = tx.add_request_body(&params.body);
        let _ = tx.process_request_headers();
        let _ = tx.process_request_body();
        let it = tx
            .intervention()
            .expect("Must be able to check for intervention");
        let _ = tx.process_logging();
        if let Some(sender) = sender {
            let _ = sender.send(it);
        }
    });
}

impl UserFilter for ModSecurityWAF {
    const METHODS: u8 =
        FilterMethod::HTTP_HEADERS | FilterMethod::HTTP_PAYLOAD | FilterMethod::HTTP_END;
    const CONTINUE_IF_ERROR: bool = true;

    fn new(_lua: &mlua::Lua, args: mlua::Table) -> mlua::Result<Self> {
        let mut result = Self::default();
        for arg in args.clone().sequence_values::<String>() {
            match &*arg? {
                "blocking" => result.blocking = true,
                arg if arg.strip_prefix("max_body_size:").is_some() => {
                    result.request_body_max_size = arg
                        .strip_prefix("max_body_size:")
                        .map(|s| s.parse().ok())
                        .flatten()
                }
                _ => (),
            }
        }
        Ok(result)
    }

    fn http_headers(
        &mut self,
        lua: &mlua::Lua,
        txn: haproxy_api::Txn,
        msg: haproxy_api::HttpMessage,
    ) -> mlua::Result<haproxy_api::FilterResult> {
        if msg.is_resp().unwrap_or_default() {
            return Ok(haproxy_api::FilterResult::Continue);
        }
        let header_pairs = msg
            .get_headers()
            .expect("Must be able to get header")
            .pairs();
        self.current_headers.clear();
        for header in header_pairs {
            let header: (String, Vec<String>) = header?;
            self.current_headers.push(header);
        }
        Self::register_data_filter(lua, txn, msg.channel()?)?;
        Ok(haproxy_api::FilterResult::Continue)
    }

    fn http_payload(
        &mut self,
        _lua: &mlua::Lua,
        txn: haproxy_api::Txn,
        msg: haproxy_api::HttpMessage,
    ) -> mlua::Result<Option<usize>> {
        let url = txn.f.get::<_, String>("url", ())?;
        let server_addr = txn.f.get::<_, String>("be_name", ())?;
        let client_ip = txn.f.get::<_, String>("src", ())?;
        let client_port = txn.f.get::<_, u16>("src_port", ())?;
        let method = txn.f.get::<_, String>("method", ())?;
        let id = txn.f.get::<_, String>("unique_id", ())?;
        let version = txn
            .f
            .get::<_, String>("req_ver", ())
            .unwrap_or("1.1".to_string());
        let body = msg
            .body(None, Some(self.request_body_max_size.unwrap_or(5_000_000)))?
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let headers = self.current_headers.clone();
        let params = CheckRequestParams {
            uri: url,
            headers,
            body,
            client_ip,
            client_port,
            server_addr,
            method,
            version,
            id,
        };
        if self.blocking {
            let (sender, receiver) = mpsc::channel::<Intervention>();
            POOL.spawn(|| check_request(params, Some(sender)));
            match receiver.recv_timeout(Duration::from_secs(3)) {
                Ok(it) => {
                    self.intervention = Some(it);
                }
                Err(_) => {
                    self.intervention = Some(Intervention {
                        status: 403,
                        pause: false,
                        url: "".into(),
                        log: "".into(),
                        disruptive: true,
                    })
                }
            }
        } else {
            POOL.spawn(|| check_request(params, None));
        }

        Ok(None)
    }

    fn http_end(
        &mut self,
        _lua: &mlua::Lua,
        _txn: haproxy_api::Txn,
        _msg: haproxy_api::HttpMessage,
    ) -> mlua::Result<haproxy_api::FilterResult> {
        match &self.intervention {
            Some(it) if it.disruptive || it.status == 403 => Ok(haproxy_api::FilterResult::Error),
            _ => Ok(haproxy_api::FilterResult::Continue),
        }
    }
}
