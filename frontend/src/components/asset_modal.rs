//! Asset identity fields shown in the viewer's asset form.

use crate::model::AssetInfo;

/// (field key, label) for each editable asset identity field.
pub(crate) const ASSET_FIELDS: [(&str, &str); 4] =
    [("hostname", "Hostname"), ("ip", "IP Address"), ("mac", "MAC Address"), ("fqdn", "FQDN")];

pub(crate) fn asset_field<'a>(info: &'a AssetInfo, key: &str) -> &'a str {
    match key {
        "hostname" => &info.hostname,
        "ip" => &info.ip,
        "mac" => &info.mac,
        "fqdn" => &info.fqdn,
        _ => "",
    }
}

/// Copy of `info` with the field named `key` replaced.
pub(crate) fn with_asset_field(info: &AssetInfo, key: &str, value: String) -> AssetInfo {
    let mut next = info.clone();
    match key {
        "hostname" => next.hostname = value,
        "ip" => next.ip = value,
        "mac" => next.mac = value,
        "fqdn" => next.fqdn = value,
        _ => {}
    }
    next
}
