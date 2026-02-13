use anyhow::{anyhow, Context, Result};
use ssh2::Session;
use std::io::Read;

pub fn run_command(
    host: &str,
    port: u16,
    user: &str,
    key_path: Option<&str>,
    password: Option<&str>,
    command: &str,
) -> Result<(String, String, i32)> {
    let tcp = std::net::TcpStream::connect(format!("{}:{}", host, port))
        .with_context(|| format!("Failed to connect to {}:{}", host, port))?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake()?;

    let mut authenticated = false;

    if let Some(key) = key_path {
        authenticated = sess
            .userauth_pubkey_file(user, None, std::path::Path::new(key), None)
            .is_ok()
            && sess.authenticated();
    }

    if !authenticated {
        authenticated = sess.userauth_agent(user).is_ok() && sess.authenticated();
    }

    if !authenticated {
        if let Some(pass) = password {
            authenticated = sess.userauth_password(user, pass).is_ok() && sess.authenticated();
        }
    }

    if !authenticated {
        return Err(anyhow!("Authentication failed for {}@{}", user, host));
    }

    let mut channel = sess.channel_session()?;
    channel.exec(command)?;

    let mut stdout = String::new();
    let mut stderr = String::new();
    channel.read_to_string(&mut stdout)?;
    channel.stderr().read_to_string(&mut stderr)?;

    channel.wait_close()?;
    let exit_code = channel.exit_status()?;

    Ok((stdout, stderr, exit_code))
}
