use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Codebreaker)]
pub struct JsCodebreaker(codebreaker::Codebreaker);

#[wasm_bindgen(js_class = Codebreaker)]
impl JsCodebreaker {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(codebreaker::Codebreaker::new())
    }

    #[wasm_bindgen(js_name = autoDecryptCode)]
    pub fn auto_decrypt_code(&mut self, code: JsCode) -> JsCode {
        self.0.auto_decrypt_code(code.addr, code.val).into()
    }
}

#[wasm_bindgen(js_name = Code)]
pub struct JsCode {
    pub addr: u32,
    pub val: u32,
}

#[wasm_bindgen(js_class = Code)]
impl JsCode {
    #[wasm_bindgen(constructor)]
    pub fn new(addr: u32, val: u32) -> Self {
        Self { addr, val }
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{:08X} {:08X}", self.addr, self.val)
    }
}

impl From<(u32, u32)> for JsCode {
    fn from(code: (u32, u32)) -> Self {
        Self {
            addr: code.0,
            val: code.1,
        }
    }
}
