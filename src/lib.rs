use log::trace;
use log::debug;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(MyRootContext) });
}

struct MyRootContext;

impl Context for MyRootContext {}

impl RootContext for MyRootContext {
    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(MyHttpContext { context_id }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct MyHttpContext {
    context_id: u32,
}

impl Context for MyHttpContext {}

impl HttpContext for MyHttpContext {
    fn on_http_request_headers(&mut self, _: usize) -> Action {
        for (name, value) in &self.get_http_request_headers() {
            trace!("#{} -> {}: {}", self.context_id, name, value);
        }

        self.add_http_request_header("blubb", "downstream");

        /* match self.get_http_request_header(":path") {
             Some(path) if path == "/hello" => {
                 self.send_http_response(
                     200,
                     vec![("Hello", "World"), ("Powered-By", "proxy-wasm")],
                     Some(b"Hello, World!\n"),
                 );
                 Action::Pause
             }
             _ => Action::Continue,
         }*/
        // last expression is implicit returned
         Action::Continue
    }

    fn on_http_response_headers(&mut self, _: usize) -> Action {
        for (name, value) in &self.get_http_response_headers() {
            trace!("#{} <- {}: {}", self.context_id, name, value);
        }
        self.add_http_response_header("blah", "upstream");
        // last expression is implicit returned. Same as return Action::Continue;
        Action::Continue
    }

    fn on_log(&mut self) {
        debug!("#{} completed.", self.context_id);
    }
}