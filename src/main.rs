use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
    println!("[INFO] Generating WireGuard keys...");
    let (priv_key_b64, pub_key_b64) = generate_wireguard_keypair();

    println!("[INFO] Registering in Cloudflare WARP API...");
    let (client_ipv4, client_ipv6, peer_pub, private_key) =
        match register_warp(&priv_key_b64, &pub_key_b64) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                wait_for_enter();
                std::process::exit(1);
            }
        };

    let conf = build_config(&private_key, &client_ipv4, &client_ipv6, &peer_pub);
    let vpn_key = build_amnezia_vpn_key(&conf, &private_key, &client_ipv4, &client_ipv6, &peer_pub);

    println!("\n########## CODE FOR AMNEZIAVPN ##########");
    println!("{vpn_key}");
    println!("########### END OF CODE FOR AMNEZIAVPN ###########\n\n\n");

    println!("########## CONFIG FOR AMNEZIAWG ##########");
    println!("{conf}");
    println!("########### END OF CONFIG ###########\n");

    let filename = format!(
        "warp_{}.conf",
        chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
    );
    let out_path = exe_dir().join(&filename);

    match std::fs::write(&out_path, &conf) {
        Ok(_) => println!("[INFO] Config saved: {}", out_path.display()),
        Err(e) => eprintln!("[WARN] Unable to save {}: {e}", out_path.display()),
    }

    wait_for_enter();
}

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

fn wait_for_enter() {
    print!("\nPress Enter to exit...");
    let _ = std::io::stdout().flush();
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);
}

fn generate_wireguard_keypair() -> (String, String) {
    let mut private_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut private_bytes);

    private_bytes[0] &= 248;
    private_bytes[31] &= 127;
    private_bytes[31] |= 64;

    let secret = StaticSecret::from(private_bytes);
    let public = PublicKey::from(&secret);

    let priv_b64 = STANDARD.encode(private_bytes);
    let pub_b64 = STANDARD.encode(public.as_bytes());
    (priv_b64, pub_b64)
}

fn register_warp(
    priv_b64: &str,
    pub_b64: &str,
) -> Result<(String, String, String, String), Box<dyn std::error::Error>> {
    let api = "https://api.cloudflareclient.com/v0i1909051800";
    let client = reqwest::blocking::Client::new();

    let tos = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let body = json!({
        "install_id": "",
        "tos": tos,
        "key": pub_b64,
        "fcm_token": "",
        "type": "ios",
        "locale": "en_US"
    });

    let resp: Value = client
        .post(format!("{api}/reg"))
        .header("User-Agent", "okhttp/3.12.1")
        .header("Content-Type", "application/json")
        .json(&body)
        .send()?
        .json()?;

    let id = resp["result"]["id"].as_str().unwrap_or("");
    let token = resp["result"]["token"].as_str().unwrap_or("");

    if id.is_empty() || token.is_empty() {
        return Err(format!("Ошибка регистрации: {}", serde_json::to_string_pretty(&resp)?).into());
    }

    let patch_body = json!({"warp_enabled": true});
    let resp2: Value = client
        .patch(format!("{api}/reg/{id}"))
        .header("User-Agent", "okhttp/3.12.1")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .json(&patch_body)
        .send()?
        .json()?;

    let peer_pub = resp2["result"]["config"]["peers"][0]["public_key"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let client_ipv4 = resp2["result"]["config"]["interface"]["addresses"]["v4"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let client_ipv6 = resp2["result"]["config"]["interface"]["addresses"]["v6"]
        .as_str()
        .unwrap_or("")
        .to_string();

    if peer_pub.is_empty() || client_ipv4.is_empty() {
        return Err("Failed to get peer parameters from API response".into());
    }

    Ok((client_ipv4, client_ipv6, peer_pub, priv_b64.to_string()))
}

fn build_config(priv_key: &str, ipv4: &str, ipv6: &str, peer_pub: &str) -> String {
    let i1_hex = "b 0xC50000000114561F770D1828D2ED971AAC854B64CA2DAA9DFACC144484E29D57118FC0E3106227BAC93CE86BBD4DF3008000047C96A83CF0F2BD3F7325B122570306230E58B3AD20267F5027BFE4A742A591858739316A884B9C132CD5B51B9C003B0ADF1DC20DDA89F25743BCCE6DD7747D1F45225E1BC1961C0F6E58A6323AFB7ABD953B09D6E1585F82D88C990782077820092171C2C4F0A27A831A30F2895F372C534D940553E579156BC4888DA36A3672DA886639F93E822AFFF20353E2E158DA006A48D568A5E2C5B1CC14661371C7493DC121B0AD9A6726A460866D26B19C4505D65959135E4A6CBC7DF6E172DF9A2CC49A02D7F7A88AE409B3CE6439959A4881C56847D1C6C3EFA65E065D7FFD999D49475E289D51DC9CCA8EB85DB21142E2CD60BAA3127F27B91BE928CBCAB6CE525335D929A24848E948CD6962E132FF704A64AD6AAD04DFB55B08967CD512608984699C91775A137054EE9677A55F283DA180550E76C16864F510610D3FB0D0FD42ED9B72A0FAEB7E274CD7C16A465DF1A90C2BA640E1A20FCFA242AA4EEFEB068FEBB4841818490E8A9C41363FFD1483A79E2FFEB4CD5E7C9B4A60F6B4B8F6B6FF10871D0B808174F095C6B0BFF366CD1B15F5EFB56B5CA4FEF7AB78872A8726B450673B1A7FAF0A662361D8C3E77768020926911E47EFDCF06D66C530323427590B26F8BAC3C5D0C120151CA72907DFD34CE5E0776F819D37211798D258652BB4F01B6DDCE9D79909B462ADCFDC3DC6E8FB555DA1EDAF77E29FDE28E20E76B5E856629E1F972C706AC7ACDBEF0C2B2BF5BAC0D3467BBCD9AC94DCC11D69DA822E695D805D68273F24A4D1FB8B1BA437B56B4BEAE165CA39C00227EF55262943A116E07C463B59ACC2491B27A9082E919C7491303C3EAAED1D9DE2B6F49804B6DDE6DA1174060114FC8FB01EE9B3392C646C1BAB1449096C79E6DC705C997D150F9CC8A7DAC290B60570CB6D746CE9242E7B0D8099A8D8EE1E598584714204522C3198A637903AF905D263E2E5D2C1887BA8417E600472F9296A298EAE86945BAC04DA17EF0D73CEB81CF89D5532F30267B55D8B62B080E9F69E828D7E056F1C7C6F088EA4286A564651F69975D1DE317893EAB722CDC09B4426D169CC90C9A762CBD6BE7137BB56999B0ABCB4D7D200ADEAFE6C9CD46EB612C49EAEC0B1FC0CE970541B45E708B9EAE6F1D33D0AC4ED4D58C263865E7C2ADF9E1E7A46F3500383B447F26DDB389924BEAAA46AB6AC7A49FF599F2FC40DE334983CB890F7AA62D528E89FD5E75E474D3B4EE495A1335581B0E0FD5D03DF5AED08295AD2C95A29BF548622740AA5C05446692CF8F6595BDEF7855944B1822D565F37A5D33DD796E358B7743F3275D4DB70BF600D4EF749F7605B82509B8DC4AFFC2C3C3C280292021F470DC17B5A547F68474736EE8C198FEC1E3F5186A9616ED0C69643F2C618F5B199F0D50A27E9776EA234FF8697FC57F2D256A67A8FDC1F26BDA291D66D5AF79B09DC92B40E7050F3F7A71F6AEE873876DEFBB146631AFDEAEFEF2DE6B0EAD67496B4FD97FF131F9E05385552CB7FE18C534A0E72DD1AA1C4CB903571BE5EF915216E95083914365262D0D271FC3D65823BAA82DDEF382E1845CCFCCC8F8064F804E106C2F27B42C6845F536AE3F17B1746D8E874B5B68B874951B1";

    format!(
        r#"[Interface]
PrivateKey = {priv_key}
S1 = 0
S2 = 0
Jc = 120
Jmin = 23
Jmax = 911
H1 = 1
H2 = 2
H3 = 3
H4 = 4
MTU = 1280
I1 = {i1_hex}
Address = {ipv4}, {ipv6}
DNS = 1.1.1.1, 2606:4700:4700::1111, 1.0.0.1, 2606:4700:4700::1001

[Peer]
PublicKey = {peer_pub}
AllowedIPs =  ::/1, 8000::/1, 0.0.0.0/1, 128.0.0.0/1
Endpoint = 162.159.192.1:500
"#
    )
}

fn build_amnezia_vpn_key(
    conf: &str,
    priv_key: &str,
    ipv4: &str,
    ipv6: &str,
    peer_pub: &str,
) -> String {
    let i1_val = conf
        .lines()
        .find(|l| l.starts_with("I1 = "))
        .map(|l| l.trim_start_matches("I1 = "))
        .unwrap_or("");

    let config_with_crlf = conf.replace('\n', "\r\n");

    let awg_json = json!({
        "H1": "1", "H2": "2", "H3": "3", "H4": "4",
        "I1": i1_val,
        "Jc": "120", "Jmax": "911", "Jmin": "23",
        "S1": "0", "S2": "0",
        "allowed_ips": ["::/1", "8000::/1", "0.0.0.0/1", "128.0.0.0/1"],
        "client_ip": format!("{ipv4}, {ipv6}"),
        "client_priv_key": priv_key,
        "config": config_with_crlf,
        "hostName": "162.159.192.1",
        "mtu": 1280,
        "port": 500,
        "server_pub_key": peer_pub
    });

    let amnezia_json = json!({
        "containers": [{
            "container": "amnezia-awg",
            "awg": {
                "isThirdPartyConfig": true,
                "last_config": awg_json,
                "port": "500",
                "transport_proto": "udp"
            }
        }],
        "defaultContainer": "amnezia-awg",
        "description": "Cloudflare WARP",
        "hostName": "162.159.192.1"
    });

    let encoded = STANDARD.encode(amnezia_json.to_string().as_bytes());
    format!("vpn://{encoded}")
}