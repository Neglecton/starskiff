//! Embedded admin console (Vue 3 build output; a placeholder index.html is
//! committed so cargo works before `npm run build` — see web/README).

use rust_embed::Embed;

#[derive(Embed)]
#[folder = "web/dist/"]
pub struct AdminAssets;
