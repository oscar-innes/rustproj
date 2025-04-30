use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use ipgeolocate::{Locator, Service};
use regex::Regex;
use std::path::Path;
use chrono::{NaiveDateTime, DateTime, Utc, Duration, Timelike};
use std::collections::{HashMap, VecDeque};
use async_std::task;
use tokio::runtime::Runtime;
use lettre::{transport::smtp::authentication::Credentials, Message, SmtpTransport, Transport};
use lettre::message::{Mailbox, MultiPart, SinglePart};
use dotenv::dotenv;

//figure out the fix
//add more patterns like 3 more probs
//get the logs streamlined with the features
// get the formatting fixed
// export and handle log data into json without module.



#[derive(Debug)]
struct BasicLog {
    time: String,
    severity: String,
    info: String,
}

struct FailedLogin {
    timestamp: DateTime<Utc>
}

#[derive(Debug)]
struct WinEvnt {
    time: String,
    severity: String,
    info: String,
}

#[derive(Debug)]
struct SysLog {
    month: u32,
    day: u32,
    time: String,
    hostname: String,
    p_name: String,
    pid: u32,
    msg: String
}

#[derive(Debug)]
struct Apache {
    ip: String,
    user: String,
    time: String,
    http: String,
    url: String,
    version: String,
    code: u32,
    size: u64
}

#[derive(Debug)]
struct Nginx {
    ip: String,
    time: String,
    method: String,
    url: String,
    protocol: String,
    code: u32,
    size: u64,
    refer: String,
    agent: String
}

pub const email: &str = "innesoscar@gmail.com";  //add the email you want to use to recieve the alerts.

fn main() {
    let args: Vec<String> = env::args().collect();
    match args[1].as_str() {
        "parse" => {
            match args[2].as_str() {
                "live" => {
                    println!("This may take a while!");
                    let _ = task::block_on(livefile());
                    async fn livefile() -> io::Result<()> {
                        println!("Analysing current system log files found.");
                        let system_logs = vec![
                        "system.log",
                        "file.txt",
                        "apache.log",
                        "/var/log/syslog",      //alter these files depending on what your system uses and what files you drag into the projects folder.
                        "/var/log/messages",    
                        "/var/log/system.log", 
                        "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
                        "C:\\Windows\\System32\\winevt\\Logs\\Windows PowerShell.evtx",
                        "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
                        ];
                        'goob: for pathing in system_logs {
                            println!("{}", pathing);
                            let paf = pathing.to_string();
                            let syslog = match File::open(pathing) {
                                Ok(file) => file,
                                Err(err) => {
                                    continue 'goob;
                                }
                            };
                            let read = BufReader::new(syslog);
                            let path = Path::new(&paf);
                            match path.extension().and_then(|s| s.to_str()) {
                                Some("txt")  => {
                                    let basic_log = Regex::new(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) \[(\w+)\] ([\w\.]+): (.+)$").unwrap();
                                    let mut user_attempts: Vec<DateTime<Utc>> = Vec::new();
                                    for lin in read.lines() {
                                        let analysed_line = lin?;
                                        println!("{}", analysed_line);
                                        if let Some(reggie) = &basic_log.captures(&analysed_line) {
                                            let log = BasicLog {
                                                time: reggie.get(1).unwrap().as_str().to_string(),
                                                severity: reggie.get(2).unwrap().as_str().to_string(),
                                                info: reggie.get(3).unwrap().as_str().to_string(),
                                            };
                                            if log.info.to_lowercase().contains("login") || log.info.to_lowercase().contains("logon") && log.info.to_lowercase().contains("failed") {
                                                println!("I caught a bad logon attempt");
                                                if let Ok(timestamp) = DateTime::parse_from_str(&log.time, "%Y-%m-%d %H:%M:%S") {
                                                    let timestamp_utc = timestamp.with_timezone(&Utc);
                                                    user_attempts.push(timestamp_utc);
                                                }
                                            }  
                                        } else {
                                            println!("Issues");
                                            continue 'goob;
                                        }
                                    }
                                    user_attempts.sort();
                                    if user_attempts.len() >= 5 {
                                        for i in 0..user_attempts.len() - 4 {
                                            let start = user_attempts[i];
                                            let end = user_attempts[i + 4];
                                            if end <= start + Duration::minutes(1) {
                                                let message = format!("Potential BruteForce attack detected at: {} to {}", start, end);
                                                let _ = create_alert(&message);
                                            }
                                        }
                                    }
                                    return Ok(())
                                }
                                Some("evtx") => {
                                    let basic_log = Regex::new(r"^\[(.*?)\]\s+(\w+):\s+(.*)$").unwrap();
                                    let mut user_attempts: Vec<DateTime<Utc>> = Vec::new();
                                    for lin in read.lines() {
                                        let analysed_line = lin?;
                                        if let Some(reggie) = &basic_log.captures(&analysed_line) {
                                            let log = WinEvnt {
                                                time: reggie.get(1).unwrap().as_str().to_string(),
                                                severity: reggie.get(2).unwrap().as_str().to_string(),
                                                info: reggie.get(3).unwrap().as_str().to_string(),
                                            };
                                            if log.info.to_lowercase().contains("login") || log.info.to_lowercase().contains("logon") && log.info.to_lowercase().contains("failed") {
                                                println!("I caught a bad logon attempt");
                                                if let Ok(timestamp) = DateTime::parse_from_str(&log.time, "%Y-%m-%d %H:%M:%S") {
                                                    let timestamp_utc = timestamp.with_timezone(&Utc);
                                                    user_attempts.push(timestamp_utc);
                                                }
                                            }
                                            println!("log {:?}", log);
                                        } else {
                                            println!("Issues");
                                            continue 'goob;
                                        }
                                    }
                                    user_attempts.sort();
                                    if user_attempts.len() >= 5 {
                                        for i in 0..user_attempts.len() - 4 {
                                            let start = user_attempts[i];
                                            let end = user_attempts[i + 4];
                                            if end <= start + Duration::minutes(1) {
                                                let message = format!("Potential BruteForce attack detected at: {} to {}", start, end);
                                                let _ = create_alert(&message);
                                            }
                                        }
                                    }
                                    return Ok(())
                                }
                                Some("syslog") | Some("messages") => {
                                    let sissy = Regex::new(r"^(\w{3})\s+(\d{1,2})\s([\d:]{8})\s([\w\-.]+)\s(\S+)\[(\d+)\]:\s(.+)$").unwrap();
                                    for lin in read.lines() {
                                        let analysed_line = lin?;
                                        if let Some(crapola) = &sissy.captures(&analysed_line) {
                                            let log = SysLog {
                                                month: crapola.get(1).unwrap().as_str().parse().unwrap(),
                                                day: crapola.get(2).unwrap().as_str().parse().unwrap(),
                                                time: crapola.get(3).unwrap().as_str().to_string(),
                                                hostname: crapola.get(4).unwrap().as_str().to_string(),
                                                p_name: crapola.get(5).unwrap().as_str().to_string(),
                                                pid: crapola.get(6).unwrap().as_str().parse().unwrap(),
                                                msg: crapola.get(7).unwrap().as_str().to_string(),
                                            };
                                            println!("log {:?}", log);
                                        } else {
                                            println!("Issues");
                                            continue 'goob;
                                        }
                                    }
                                    return Ok(())
                                }
                                Some("log") => {
                                    let nginx = Regex::new(r#"^(\S+) \S+ \S+ \[([^\]]+)\] \"(\S+) (.*?) (\S+)\" (\d{3}) (\d+) \"([^\"]*)\" \"([^\"]*)\""#).unwrap();
                                    let apache = Regex::new(r#"^(\S+) (\S+) (\S+) \[([^\]]+)\] \"(\S+) (.*?) (\S+)\" (\d{3}) (\d+|-)$"#).unwrap();
                                    let other = Regex::new(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] ([\w\.]+): (.+)$").unwrap();
                                    let mut user_attempts: Vec<DateTime<Utc>> = Vec::new();
                                    let agents = ["curl", "wget", "python", "scrapy", "httpclient"];
                                    let suspicious_paths = ["/etc/passwd", "/var/www/", "../", "' OR 1=1 --", "UNION SELECT", "%27", "--", ";--", ";", "&&", "|", "%3B", "%26%26", "%7C"];
                                    for lin in read.lines() {
                                        let analysed_line = lin?;
                                        if let Some(ga) = &nginx.captures(&analysed_line) {
                                            let log = Nginx {
                                                ip: ga.get(1).unwrap().as_str().to_string(),
                                                time: ga.get(2).unwrap().as_str().to_string(),
                                                method: ga.get(3).unwrap().as_str().to_string(),
                                                url: ga.get(4).unwrap().as_str().to_string(),
                                                protocol: ga.get(5).unwrap().as_str().to_string(),
                                                code: ga.get(6).unwrap().as_str().parse().unwrap(),
                                                size: ga.get(7).unwrap().as_str().parse().unwrap(),
                                                refer: ga.get(8).unwrap().as_str().to_string(),
                                                agent: ga.get(9).unwrap().as_str().to_string(),
                                            };
                                            if log.url.to_lowercase().contains("login") || log.url.to_lowercase().contains("logon"){
                                                println!("I caught a bad logon attempt");
                                                if let Ok(timestamp) = DateTime::parse_from_str(&log.time, "%Y-%m-%d %H:%M:%S") {
                                                    let timestamp_utc = timestamp.with_timezone(&Utc);
                                                    if timestamp_utc.hour() < 5{
                                                        let message = format!("Suspicious logon activity detected: {}", &log.time);
                                                        let _ = create_alert(&message);
                                                    } else {
                                                        println!("error");
                                                    }
                                                    if log.code == 401 {
                                                        user_attempts.push(timestamp_utc);
                                                    } else {
                                                        println!("error");
                                                    }
                                                } else {
                                                    println!("error");
                                                }

                                            }

                                            let worker = log.agent.to_lowercase();
                                            if worker.trim().is_empty() || agents.iter().any(|a| worker.contains(a)) {
                                                let message = format!("Unusual user agent detected to access the site: {} at {}", &worker, &log.time);
                                                let _ = create_alert(&message);
                                            }

                                            let ip = log.ip.clone();
                                            let (nation, country) = task::block_on(locate(ip));
                                            if nation {
                                                let message = format!("Suspicious logon activity from a blacklisted country: {}", &country);
                                                let _ = create_alert(&message);
                                            }
                                        } else if let Some(ga) = &apache.captures(&analysed_line) {
                                            let log = Apache {
                                                ip: ga.get(1).unwrap().as_str().to_string(),
                                                user: ga.get(3).unwrap().as_str().to_string(),
                                                time: ga.get(4).unwrap().as_str().to_string(),
                                                http: ga.get(5).unwrap().as_str().to_string(),
                                                url: ga.get(6).unwrap().as_str().to_string(),
                                                version: ga.get(7).unwrap().as_str().to_string(),
                                                code: ga.get(8).unwrap().as_str().parse().unwrap(),
                                                size: ga.get(9).unwrap().as_str().parse().unwrap(),
                                            };

                                            if log.url.to_lowercase().contains("login") || log.url.to_lowercase().contains("logon") {
                                                println!("I caught a bad logon attempt");
                                                if let Ok(timestamp) = DateTime::parse_from_str(&log.time, "%d/%b/%Y:%H:%M:%S %z") {
                                                    println!("date parsed");
                                                    let timestamp_utc = timestamp.with_timezone(&Utc);
                                                    if timestamp_utc.hour() < 5{
                                                        println!("log");
                                                        let message = format!("Suspicious logon activity detected: {}", &log.time);
                                                        let _ = create_alert(&message);
                                                    }
                                                    if log.code == 401 {
                                                        println!("Code");
                                                        let _ = user_attempts.push(timestamp_utc);
                                                    }

                                                }
                                            }
                                            let ip = log.ip.clone();
                                            let rt = Runtime::new().unwrap();
                                            let (nation, country) = rt.block_on(async {;
                                                locate(ip).await
                                            });
                                            if nation {
                                                let message = format!("System accessed from a suspicious country: {}", &country);
                                                let _ = create_alert(&message);
                                            }

                                            if log.url.contains(patterns) {
                                                let message = format!("A suspicious attack pattern attempt was detected within logs: {} at {}", &log.url ,&log.time);
                                                let _ = create_alert(&message);
                                            }

                                        } else if let Some(ga) = &other.captures(&analysed_line) {
                                            let log = BasicLog {
                                                time: ga.get(1).unwrap().as_str().to_string(),
                                                severity: ga.get(2).unwrap().as_str().to_string(),
                                                info: ga.get(4).unwrap().as_str().to_string(),
                                            };
                                            if let Ok(timestamp) = DateTime::parse_from_str(&log.time, "%Y-%m-%d %H:%M:%S") {
                                                let timestamp_utc = timestamp.with_timezone(&Utc);
                                                if timestamp_utc.hour() < 5{
                                                    let message = format!("Suspicious logon activity detected: {}", &log.time);
                                                    let _ = create_alert(&message);
                                                }

                                            }

                                        } else {
                                            eprintln!("Unrecognised log format for file: {}", pathing);
                                            continue 'goob;
                                        }
                                    
                                    }
                                    user_attempts.sort();
                                    if user_attempts.len() >= 5 {
                                        for i in 0..user_attempts.len() - 4 {
                                            let start = user_attempts[i];
                                            let end = user_attempts[i + 4];
                                            if end <= start + Duration::minutes(1) {
                                                let message = format!("Potential BruteForce attack detected at: {} to {}", start, end);
                                                let _ = create_alert(&message);
                                            }
                                        }
                                    }
                                    return Ok(())
                                }
                                _ => {
                                    eprintln!("Unsupported file extension for file: {}", pathing);
                                }
                            }
                        continue 'goob
                        }
                        return Ok(())
                    }

                },
                "export" => {
                    match args[4].as_str() {
                        "csv" => {

                        },
                        "json" => {

                        }
                        _ => println!("Exiting...")
                    }
                }
                _ => println!("Exiting...")
            }

        },
        "alerts" => {
            println!("Alerts here");
        },
        "help" => {
            println!("Command list")
        }
        _ => println!("Exiting...")
    }
}

fn create_alert(message: &str) -> std::result::Result<(), Box<dyn std::error::Error>>{
    println!("Alert started...");
    dotenv().ok();  
    let mail = Message::builder().from("rustalyzer@gmail.com".parse()?).to(email.parse().unwrap()).subject("Security Alert from logs").body(message.to_string()).unwrap();
    let key = env::var("API_KEY").unwrap();
    let info = Credentials::new(
        "apikey".to_string(),
        key,
    );
    let mailer = SmtpTransport::starttls_relay("smtp.sendgrid.net")? 
        .credentials(info)
        .build();

    match mailer.send(&mail) {
        Ok(_) => println!("Email sent successfully!"),
        Err(e) => eprintln!("Could not send email: {:?}", e),
    }
    
    Ok(())
}

async fn locate(ip: String) -> (bool, String) {
    let service = Service::IpApi;
    let problematic = vec![
        "iran",
        "russia",
        "north korea", //customise as you need
        "ukraine",
        "belarus",
        "turkey",
        "israel"
    ];
    let protocol = match Locator::get(&ip, service).await {
        Ok(protocol) => protocol,
        Err(error) => {
            return (false, false.to_string());
        }
    };
    if problematic.contains(&protocol.country.to_lowercase().as_str()) {
        return (true, protocol.country.to_string());
    } else {
        return (false, false.to_string());
    }
    
}


