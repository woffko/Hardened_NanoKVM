use std::os::unix::net::UnixDatagram;

const SYSLOG_SOCKET: &str = "/dev/log";
const TAG: &str = "hardened-nanokvm-auth";

pub fn test_message(source: &str) {
    emit(
        14,
        &format!(
            "hardened-nanokvm: test syslog message source={}",
            sanitize(source)
        ),
    );
}

pub fn login_success(username: &str, source_ip: &str) {
    emit(
        86,
        &format!(
            "{TAG}: web login success user={} source={}",
            sanitize(username),
            sanitize(source_ip)
        ),
    );
}

pub fn login_failure(username: &str, source_ip: &str, reason: &str) {
    emit(
        84,
        &format!(
            "{TAG}: web login failure user={} source={} reason={}",
            sanitize(username),
            sanitize(source_ip),
            sanitize(reason)
        ),
    );
}

fn emit(priority: u8, message: &str) {
    let payload = format!("<{priority}>{message}");
    let Ok(socket) = UnixDatagram::unbound() else {
        return;
    };
    let _ = socket.send_to(payload.as_bytes(), SYSLOG_SOCKET);
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter_map(|ch| {
            if ch.is_ascii_graphic() && ch != '"' && ch != '\'' && ch != '\\' {
                Some(ch)
            } else if ch.is_ascii_whitespace() {
                Some('_')
            } else {
                None
            }
        })
        .take(128)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_audit_fields() {
        assert_eq!(sanitize("admin root\nx"), "admin_root_x");
        assert_eq!(sanitize("bad\"quote"), "badquote");
    }
}
