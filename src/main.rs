use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::str::FromStr;

use domain::base::iana::{Class, Rcode};
use domain::base::{Message, MessageBuilder, Record, ToName, Ttl};
use domain::rdata::A;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::prelude::Peripherals;
use esp_idf_svc::log::EspLogger;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::wifi::*;
use log::info;

const SSID: &str = "";
const PASSWORD: &str = "";

fn connect_wifi(wifi: &mut BlockingWifi<EspWifi<'static>>) {
    let wifi_configuration: Configuration = Configuration::Client(ClientConfiguration {
        ssid: SSID.try_into().unwrap(),
        bssid: None,
        auth_method: AuthMethod::WPA2Personal,
        password: PASSWORD.try_into().unwrap(),
        channel: None,
        ..Default::default()
    });

    wifi.set_configuration(&wifi_configuration).unwrap();

    wifi.start().unwrap();
    info!("Wifi started");

    wifi.connect().unwrap();
    info!("Wifi connected");

    wifi.wait_netif_up().unwrap();
    info!("Wifi netif up");
}

static BLOCKED_DOMAINS: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "ad.doubleclick.net",
    "pagead2.googlesyndication.com",
];

struct SinkholeHandler;

impl SinkholeHandler {
    fn check(domain: &str) -> bool {
        if BLOCKED_DOMAINS.contains(&domain) {
            true
        } else {
            false
        }
    }

    fn resolve(msg: &Message<Vec<u8>>) -> Vec<u8> {
        let mut builder = MessageBuilder::new_vec()
            .start_answer(msg, Rcode::NOERROR)
            .unwrap();

        let _ = msg.question().map(|q| {
            // TODO: unwrap :(
            let domain_name = q.unwrap().qname().to_name::<Vec<_>>();
            // TODO: TTL maybe from config or such?
            let record = Record::new(
                domain_name,
                Class::IN,
                Ttl::from_secs(86400),
                A::from_octets(0, 0, 0, 0),
            );
            // TODO: unwrap :(
            builder.push(record).unwrap();
        });
        builder.finish()
    }
}

struct Request {
    addr: SocketAddr,
    id: u16,
}

fn handle_connection() {
    let buf_sz = 1024;

    let socket = UdpSocket::bind("0.0.0.0:53");

    let socket = match socket {
        Ok(socket) => socket,
        Err(_) => todo!(),
    };

    // TODO: From config? Now hardcoded NSA backed Cloudflare
    let upstream_socket_addr = SocketAddr::new(IpAddr::from_str("1.1.1.1").unwrap(), 53);

    let mut reqs: Vec<Request> = vec![];
    info!("Handling requests");
    loop {
        let mut buf = vec![0; buf_sz];
        let (size, recv_addr) = socket.recv_from(&mut buf).unwrap();
        buf.truncate(size);

        // Parse DNS message
        let message = match Message::from_octets(buf.clone()) {
            Ok(msg) => msg,
            Err(_) => continue,
        };

        if recv_addr == upstream_socket_addr {
            if let Some((index, request)) = reqs
                .iter()
                .enumerate()
                .find(|(_, req)| req.id == message.header().id())
            {
                socket.send_to(&buf, request.addr).unwrap();
                reqs.swap_remove(index);
            }
        } else {
            // Handle client DNS request
            let questions: Vec<_> = message.question().collect();
            let filter = questions.iter().any(|&q| {
                let domain = q.unwrap().qname().to_string();
                SinkholeHandler::check(&domain)
            });
            if filter {
                let answer = SinkholeHandler::resolve(&message);
                socket.send_to(&answer, recv_addr).unwrap();
                println!(
                    "{} filtered domain: {}",
                    recv_addr.ip(),
                    message.first_question().unwrap().qname().to_string(),
                );
            } else {
                println!(
                    "{} requested domain: {}",
                    recv_addr.ip(),
                    message.first_question().unwrap().qname().to_string(),
                );

                reqs.push(Request {
                    addr: recv_addr,
                    id: message.header().id(),
                });
                socket.send_to(&buf, upstream_socket_addr).unwrap();
            }
        }
    }
}

fn main() {
    esp_idf_svc::sys::link_patches();
    EspLogger::initialize_default();

    let peripherals = Peripherals::take().unwrap();
    let sys_loop = EspSystemEventLoop::take().unwrap();
    let nvs = EspDefaultNvsPartition::take().unwrap();

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs)).unwrap(),
        sys_loop,
    )
    .unwrap();

    connect_wifi(&mut wifi);

    let ip_info = wifi.wifi().sta_netif().get_ip_info().unwrap();

    handle_connection();
}
