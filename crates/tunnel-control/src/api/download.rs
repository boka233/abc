//! 供一键对接脚本下载 agent 二进制。
//!
//! # 为什么这个端点不需要认证
//!
//! 一键对接的顺序是「下载二进制 → 启动 agent → agent 凭组令牌注册」。下载发生在
//! 注册之前，那时目标机器上除了命令行里的组令牌之外没有任何凭据，而把组令牌放进
//! 下载 URL 会让它出现在 shell 历史、代理日志与 `ps` 输出里 —— 比不认证更糟。
//!
//! 暴露的内容是一个公开发布的二进制：不含密钥、不含配置、不含任何部署信息。能拿到
//! 它的人也能从发布页下到同一个文件。
//!
//! # 路径穿越是如何被排除的
//!
//! 架构参数**从不参与路径拼接**。它先被解析成一个只有两个取值的枚举，再由枚举给出
//! 固定的文件名常量。`../../etc/shadow` 这类输入在解析那一步就变成 `None` 并返回
//! 404，根本走不到文件系统。这比「拼完路径再检查是否越界」更可靠 —— 后者要考虑
//! 符号链接、UTF-8 归一化、平台差异，每一项都是一次出错机会。

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

/// 支持的目标架构。
///
/// 刻意只有两个取值：这两个覆盖了实际会用到的 Linux 服务器，而每多一个取值就多一个
/// 需要构建与验证的产物。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// 解析 URL 里的架构名。无法识别时返回 `None`，调用方据此回 404。
    ///
    /// 只认这两个字面值。不做前缀匹配、不做模糊匹配 —— `x86_64-something` 应当被
    /// 拒绝，而不是被当成 `x86_64`。
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "x86_64" => Some(Arch::X86_64),
            "aarch64" => Some(Arch::Aarch64),
            _ => None,
        }
    }

    /// 该架构对应的文件名。常量，不由输入拼接而来。
    fn file_name(self) -> &'static str {
        match self {
            Arch::X86_64 => "tunnel-agent-x86_64",
            Arch::Aarch64 => "tunnel-agent-aarch64",
        }
    }
}

/// 自定义响应头，脚本据此校验下载内容的完整性。
///
/// 很多部署是 `http://panel:8080`（面板在内网、前面没有 TLS 终结），此时下载一个
/// 将以 root 权限运行的可执行文件而不校验，等于接受中间人替换。
pub const SHA256_HEADER: &str = "x-binary-sha256";
pub const VERSION_HEADER: &str = "x-binary-version";

/// `GET /api/agent/download/tunnel-agent-{arch}`
pub async fn download_agent(
    State(state): State<Arc<AppState>>,
    Path(arch): Path<String>,
) -> Response {
    // 先解析再谈文件：非法输入到不了文件系统。
    let Some(arch) = Arch::parse(arch.trim()) else {
        // 统一 404 而不是 400：对扫描器而言「不支持的架构」和「没有这个端点」不该
        // 有区别，否则可以用它探测部署细节。
        tracing::debug!("agent 二进制下载：不支持的架构");
        return not_found();
    };

    let Some(dir) = state.config().agent_binary_dir.clone() else {
        // 明确记一条：管理员会遇到「一键对接说下载失败」，日志里必须能看出原因是
        // 没配目录，而不是文件缺失。
        tracing::warn!(
            "agent 二进制下载被请求，但 agent_binary_dir 未配置；\
             请在 config.toml 中设置它并放入发布包里的 agent 二进制"
        );
        return not_found();
    };

    let path: PathBuf = dir.join(arch.file_name());
    let bytes = match tokio::fs::read(&path).await {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => {
            tracing::warn!(path = %path.display(), "agent 二进制是空文件，已忽略");
            return not_found();
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "无法读取 agent 二进制；请确认发布包里的二进制已放到该目录"
            );
            return not_found();
        }
    };

    let digest = sha256_hex(&bytes);
    tracing::info!(
        arch = arch.file_name(),
        bytes = bytes.len(),
        "提供 agent 二进制下载"
    );

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_LENGTH, bytes.len().to_string()),
            (
                header::HeaderName::from_static(SHA256_HEADER),
                digest,
            ),
            (
                header::HeaderName::from_static(VERSION_HEADER),
                env!("CARGO_PKG_VERSION").to_string(),
            ),
            // 二进制按版本发布，不该被代理长期缓存 —— 升级后拿到旧文件会很难排查。
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        Body::from(bytes),
    )
        .into_response()
}

/// 所有失败路径共用的响应。
///
/// 内容一致：文件不存在、架构不支持、目录未配置对外都是同一个 404。区别只写进日志，
/// 那是给管理员看的，不是给请求方看的。
fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "未找到对应架构的 agent 二进制\n",
    )
        .into_response()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_two_supported_arches_parse() {
        assert_eq!(Arch::parse("x86_64"), Some(Arch::X86_64));
        assert_eq!(Arch::parse("aarch64"), Some(Arch::Aarch64));
    }

    #[test]
    fn path_traversal_attempts_never_become_an_arch() {
        // 这些输入若参与了路径拼接就是一个任意文件读取漏洞。解析这一步就挡掉它们，
        // 所以它们连文件系统都到不了。
        for evil in [
            "../../../etc/shadow",
            "..",
            "../x86_64",
            "x86_64/../../etc/passwd",
            "/etc/passwd",
            "x86_64%2f..%2f..%2fetc%2fpasswd",
            "\\..\\..\\windows\\system32",
            "x86_64\0",
        ] {
            assert_eq!(Arch::parse(evil), None, "危险输入被解析成了架构: {evil:?}");
        }
    }

    #[test]
    fn near_misses_are_rejected_rather_than_guessed() {
        // 不做前缀或模糊匹配：`x86` 不是 `x86_64`，猜错架构会让目标机器装上一个
        // 根本跑不起来的二进制，排查成本远高于直接报错。
        for wrong in [
            "",
            " ",
            "x86",
            "x64",
            "amd64",
            "arm64",
            "X86_64",
            "x86_64-unknown-linux-gnu",
            "aarch64-musl",
            "riscv64",
        ] {
            assert_eq!(Arch::parse(wrong), None, "不该接受 {wrong:?}");
        }
    }

    #[test]
    fn file_names_are_constants_not_derived_from_input() {
        // 文件名来自枚举而非入参，这是排除穿越的根本原因。
        assert_eq!(Arch::X86_64.file_name(), "tunnel-agent-x86_64");
        assert_eq!(Arch::Aarch64.file_name(), "tunnel-agent-aarch64");
        for a in [Arch::X86_64, Arch::Aarch64] {
            let name = a.file_name();
            assert!(!name.contains('/') && !name.contains('\\') && !name.contains(".."));
        }
    }

    #[test]
    fn sha256_matches_the_known_vector() {
        // 空输入的 SHA-256 是一个公开常量；算错的话脚本侧的校验会全部误判。
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // 十六进制必须零填充到 64 位，否则脚本比对会偶发失败。
        assert_eq!(sha256_hex(b"").len(), 64);
        assert!(sha256_hex(b"hello").chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn every_failure_path_returns_the_same_shape() {
        // 文件缺失、架构不支持、目录未配置对外是同一个 404 —— 否则可以用差异探测
        // 部署细节。
        let r = not_found();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }
}
