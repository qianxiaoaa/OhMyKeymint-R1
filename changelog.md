feat: remove UID filter, bump versionCode to 105, fix WebUI cloud helper

- Remove the Chunqiu UID filter from companion, WebUI, and docs
- Update R1 module descriptions and the keybox tool copy
- Prefer the installed module keymint binary for WebUI cloud status
- Drop unused crate dependencies so clippy -D warnings stays clean
- Default OMK_VERSION_CODE to 105
