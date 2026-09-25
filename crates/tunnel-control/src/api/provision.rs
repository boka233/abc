//! Bootstrap tunnel TLS material using the existing device-group credential.
//!
//! The CA certificate is public. Exit nodes generate their own private key and
//! submit only a CSR; the signing key never leaves the control machine.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue};
use tunnel_storage::groups::DeviceGroupRepo;
use tunnel_storage::routes::RouteRepo;
use uuid::Uuid;

use super::error::{ApiError, ApiResult};
use super::middleware::AuthAgent;
use crate::config::ControlConfig;
use crate::state::AppState;

const MAX_CSR_BYTES: usize = 16 * 1024;

pub fn server_name(node_id: &str) -> Option<String> {
    let id = Uuid::parse_str(node_id).ok()?;
    Some(format!("n{}.tunnel.internal", id.simple()))
}

pub fn managed_marker(cfg: &ControlConfig, node_id: &str) -> PathBuf {
    cfg.database_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("managed-tls")
        .join(node_id)
}

fn pem_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-pem-file"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

pub async fn ca_certificate(
    State(state): State<Arc<AppState>>,
    agent: AuthAgent,
) -> ApiResult<(HeaderMap, String)> {
    let cfg = state.config();
    let path = cfg
        .agent_tls
        .ca_path
        .as_ref()
        .ok_or_else(|| ApiError::internal("tunnel CA path is not configured"))?;
    let pem = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| ApiError::internal(format!("cannot read tunnel CA: {e}")))?;
    if !pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err(ApiError::internal(
            "tunnel CA file is not a PEM certificate",
        ));
    }
    let mut headers = pem_headers();
    headers.insert(
        "x-agent-role",
        HeaderValue::from_str(&agent.node.role)
            .map_err(|_| ApiError::internal("invalid node role"))?,
    );
    Ok((headers, pem))
}

pub async fn issue_certificate(
    State(state): State<Arc<AppState>>,
    agent: AuthAgent,
    csr: Bytes,
) -> ApiResult<(HeaderMap, String)> {
    if agent.node.role != "exit" && agent.node.role != "both" {
        return Err(ApiError::Forbidden(
            "only exit nodes may request server certificates".into(),
        ));
    }
    if csr.is_empty() || csr.len() > MAX_CSR_BYTES {
        return Err(ApiError::bad_request("invalid CSR size"));
    }
    let csr = std::str::from_utf8(&csr)
        .map_err(|_| ApiError::bad_request("CSR must be PEM text"))?
        .to_owned();
    if !csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----") {
        return Err(ApiError::bad_request(
            "CSR must be a PEM certificate request",
        ));
    }
    let name =
        server_name(&agent.node.id).ok_or_else(|| ApiError::internal("node id is not a UUID"))?;
    let cfg = state.config();
    let ca_path = PathBuf::from(
        cfg.agent_tls
            .ca_path
            .as_ref()
            .ok_or_else(|| ApiError::internal("tunnel CA path is not configured"))?,
    );
    let marker = managed_marker(&cfg, &agent.node.id);
    let name_for_signer = name.clone();
    let certificate =
        tokio::task::spawn_blocking(move || sign_csr(&ca_path, &csr, &name_for_signer, &marker))
            .await
    .map_err(|e| ApiError::internal(format!("certificate worker failed: {e}")))??;

    // The first issued certificate changes the effective SNI of routes that dial
    // this exit. Bump their entry groups so already-running agents fetch it.
    let routes = RouteRepo::new(&state.db)
        .list_for_exit_group(&agent.group.id)
        .await?;
    let groups = DeviceGroupRepo::new(&state.db);
    let mut entry_groups = std::collections::HashSet::new();
    for route in routes {
        if entry_groups.insert(route.entry_group_id.clone()) {
            groups.bump_revision(&route.entry_group_id).await?;
        }
    }

    let mut headers = pem_headers();
    headers.insert(
        "x-tls-server-name",
        HeaderValue::from_str(&name).map_err(|_| ApiError::internal("invalid TLS server name"))?,
    );
    Ok((headers, certificate))
}

fn sign_csr(ca_path: &Path, csr: &str, name: &str, marker: &Path) -> ApiResult<String> {
    let ca_key = ca_path.with_extension("key");
    if !ca_path.is_file() || !ca_key.is_file() {
        return Err(ApiError::internal(
            "tunnel CA certificate or signing key is missing",
        ));
    }
    let work = std::env::temp_dir().join(format!("tunnel-csr-{}", Uuid::new_v4()));
    std::fs::create_dir(&work)
        .map_err(|e| ApiError::internal(format!("cannot create CSR workspace: {e}")))?;
    let result = (|| {
        let csr_path = work.join("request.pem");
        let ext_path = work.join("extensions.cnf");
        let cert_path = work.join("certificate.pem");
        std::fs::write(&csr_path, csr)
            .map_err(|e| ApiError::internal(format!("cannot write CSR: {e}")))?;
        std::fs::write(
            &ext_path,
            format!("[server_cert]\nsubjectAltName = DNS:{name}\nextendedKeyUsage = serverAuth\nbasicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature,keyEncipherment\n"),
        )
        .map_err(|e| ApiError::internal(format!("cannot write certificate extensions: {e}")))?;

        let checked = Command::new("openssl")
            .args(["req", "-in"])
            .arg(&csr_path)
            .args(["-noout", "-verify"])
            .output()
            .map_err(|e| ApiError::internal(format!("cannot verify CSR: {e}")))?;
        if !checked.status.success() {
            return Err(ApiError::bad_request("CSR signature is invalid"));
        }

        let serial = format!("0x{}", Uuid::new_v4().simple());
        let signed = Command::new("openssl")
            .args(["x509", "-req", "-in"])
            .arg(&csr_path)
            .arg("-CA")
            .arg(ca_path)
            .arg("-CAkey")
            .arg(&ca_key)
            .args([
                "-set_serial",
                &serial,
                "-days",
                "825",
                "-sha256",
                "-extfile",
            ])
            .arg(&ext_path)
            .args(["-extensions", "server_cert", "-out"])
            .arg(&cert_path)
            .output()
            .map_err(|e| ApiError::internal(format!("cannot sign CSR: {e}")))?;
        if !signed.status.success() {
            return Err(ApiError::internal(format!(
                "CA signing failed: {}",
                String::from_utf8_lossy(&signed.stderr)
            )));
        }
        let pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| ApiError::internal(format!("cannot read signed certificate: {e}")))?;
        let marker_dir = marker
            .parent()
            .ok_or_else(|| ApiError::internal("invalid managed TLS marker"))?;
        std::fs::create_dir_all(marker_dir)
            .map_err(|e| ApiError::internal(format!("cannot create TLS state: {e}")))?;
        std::fs::write(marker, name)
            .map_err(|e| ApiError::internal(format!("cannot save TLS state: {e}")))?;
        Ok(pem)
    })();
    let _ = std::fs::remove_dir_all(work);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_exit_csr_with_controlled_name() {
        let work = std::env::temp_dir().join(format!("tunnel-cert-test-{}", Uuid::new_v4()));
        std::fs::create_dir(&work).unwrap();
        let ca = work.join("ca.pem");
        let ca_key = work.join("ca.key");
        let exit_key = work.join("exit.key");
        let csr = work.join("exit.csr");
        let cert = work.join("exit.pem");
        let run = |args: &[&str]| {
            let output = Command::new("openssl").args(args).output().unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        };
        run(&[
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout",
            ca_key.to_str().unwrap(), "-out", ca.to_str().unwrap(), "-days", "2",
            "-subj", "/CN=tunnel-test-ca", "-addext", "basicConstraints=critical,CA:TRUE",
        ]);
        run(&[
            "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout",
            exit_key.to_str().unwrap(), "-out", csr.to_str().unwrap(), "-subj",
            "/CN=untrusted-name", "-addext", "subjectAltName=DNS:evil.example",
        ]);
        let name = server_name("bcc7fb78-9772-40a4-beea-ae690071a7fd").unwrap();
        let pem = sign_csr(
            &ca,
            &std::fs::read_to_string(&csr).unwrap(),
            &name,
            &work.join("managed-tls/node"),
        )
        .unwrap();
        std::fs::write(&cert, pem).unwrap();
        run(&["verify", "-CAfile", ca.to_str().unwrap(), cert.to_str().unwrap()]);
        let output = Command::new("openssl")
            .args(["x509", "-in", cert.to_str().unwrap(), "-noout", "-ext", "subjectAltName"])
            .output()
            .unwrap();
        let sans = String::from_utf8(output.stdout).unwrap();
        assert!(sans.contains(&name));
        assert!(!sans.contains("evil.example"));
        assert!(work.join("managed-tls/node").exists());
        std::fs::remove_dir_all(work).unwrap();
    }
}
