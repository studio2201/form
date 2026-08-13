use reqwest::Client;
use rsa::{pkcs8::DecodePublicKey, Oaep, RsaPublicKey};
use sha2::Sha256;
use shared_frontend::{
    components::app_shell::AppShell,
    components::header::HeaderProps,
    i18n::Language,
};
use web_sys::HtmlInputElement;
use yew::prelude::*;

use crate::common::{EncryptedSubmitRequest, FormPayload};

#[function_component(FormApp)]
pub fn form_app() -> Html {
    let pub_key = use_state(|| None::<String>);
    let pub_key_clone = pub_key.clone();

    use_effect_with((), move |_| {
        let pub_key = pub_key_clone;
        wasm_bindgen_futures::spawn_local(async move {
            let client = Client::new();
            if let Ok(res) = client.get("http://127.0.0.1:3000/pubkey").send().await {
                if let Ok(text) = res.text().await {
                    pub_key.set(Some(text));
                }
            }
        });
        || ()
    });

    let header_props = HeaderProps {
        site_title: "Secure Form".to_string(),
        theme: "default".to_string(),
        language: Language::English,
        toggle_theme: Callback::from(|_| ()),
        on_language_change: Callback::from(|_| ()),
        is_authenticated: false,
        pin_required: false,
        on_logout: Callback::from(|_| ()),
        logout_tooltip: "Logout".to_string(),
        theme_toggle_tooltip: "Toggle Theme".to_string(),
        print_tooltip: "Print".to_string(),
        on_print: None,
        enable_translation: false,
        enable_themes: false,
        enable_print: false,
        print_disabled: true,
        site_url: None,
        repo: None,
        version: None,
        version_url: None,
    };

    let name_node = use_node_ref();
    let email_node = use_node_ref();
    let message_node = use_node_ref();

    let onsubmit = {
        let name_node = name_node.clone();
        let email_node = email_node.clone();
        let message_node = message_node.clone();
        let pub_key = pub_key.clone();

        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();

            let pk_pem = if let Some(pk) = (*pub_key).as_ref() {
                pk.clone()
            } else {
                return;
            };

            let name_input = name_node.cast::<HtmlInputElement>();
            let email_input = email_node.cast::<HtmlInputElement>();
            let message_input = message_node.cast::<HtmlInputElement>();

            if let (Some(n), Some(em), Some(m)) = (name_input, email_input, message_input) {
                let payload = FormPayload {
                    name: n.value(),
                    email: em.value(),
                    message: m.value(),
                };

                let json_data = if let Ok(j) = serde_json::to_string(&payload) {
                    j
                } else {
                    return;
                };

                let public_key = if let Ok(pk) = RsaPublicKey::from_public_key_pem(&pk_pem) {
                    pk
                } else {
                    return;
                };

                let mut rng = rand::thread_rng();
                let padding = Oaep::new::<Sha256>();
                if let Ok(encrypted_data) = public_key.encrypt(&mut rng, padding, json_data.as_bytes()) {
                    wasm_bindgen_futures::spawn_local(async move {
                        let client = Client::new();
                        let req = EncryptedSubmitRequest { encrypted_data };
                        let _ = client
                            .post("http://127.0.0.1:3000/submit")
                            .json(&req)
                            .send()
                            .await;
                    });
                }
            }
        })
    };

    html! {
        <AppShell
            header={header_props}
        >
            <div style="max-width: 600px; margin: 40px auto; padding: 20px;">
                <h2>{ "Secure Submission Form" }</h2>
                if pub_key.is_none() {
                    <p>{ "Loading encryption key..." }</p>
                } else {
                    <form {onsubmit} style="display: flex; flex-direction: column; gap: 15px;">
                        <input type="text" ref={name_node} placeholder="Name" required=true />
                        <input type="email" ref={email_node} placeholder="Email" required=true />
                        <input type="text" ref={message_node} placeholder="Message" required=true />
                        <button type="submit">{ "Submit Encrypted" }</button>
                    </form>
                }
            </div>
        </AppShell>
    }
}

pub fn run() {
    yew::Renderer::<FormApp>::new().render();
}
