use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, stdin, stdout, Write};
use ipgeolocate::{Locator, Service};
use regex::Regex;
use std::path::Path;
use chrono::{DateTime, Utc, Duration, Timelike};
use async_std::task;
use tokio::runtime::Runtime;
use lettre::{transport::smtp::authentication::Credentials, Message, SmtpTransport, Transport};
use dotenvy::dotenv;
use evtx::EvtxParser; //only way to work with these logs
use serde_json::Value;
use log::{info, error};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::fs::{OpenOptions};

pub const EMAIL: &str = "";  //add the email you want to use to recieve the alerts. PLEASE SET THIS OR THE PROGRAM WILL NOT WORK!
static SYSTEM_LOGS: &[&str] = &[
"test.evtx",
"system.log",
"apache.log",
"/var/log/syslog",      //alter these files depending on what your system uses and what files you drag into the projects folder.
"/var/log/messages",    
"/var/log/system.log", 
"C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
"C:\\Windows\\System32\\winevt\\Logs\\Windows PowerShell.evtx",
"C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
];


#[derive(Debug)]
struct SysLog {
    priority: i32,  
    timestamp: String,
    hostname: String,
    program: String,
    pid: i32,       
    message: String,
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

#[derive(Debug)]
struct Auth {
    timestamp: String,
    host: String,
    program: String,
    pid: i32,
    message: String,
}

fn main(){
    let mut hashioka = DefaultHasher::new();
    dotenv().ok();
    match env::var("RUSTALYZER_PASSWORD") {
        Ok(password) => {
            println!("Enter your orginisations password!");
            let mut pass = String::new();
            let _ = stdout().flush();
            stdin().read_line(&mut pass).expect("Did not enter a correct string");
            pass.hash(&mut hashioka);
            let stored = hashioka.finish();  
            while stored.to_string() != password {
                stdin().read_line(&mut pass).expect("Did not enter a correct string");
                pass.hash(&mut hashioka);
                let stored = hashioka.finish(); 
            }
            println!("Logged in successfully! Scan is about to begin!")
        },
        Err(_) => {
            println!("It appears you do not have a password set for your orginisation, Please enter one below!");
            let mut pass = String::new();
            let _ = stdout().flush();
            stdin().read_line(&mut pass).expect("Did not enter a correct string");
            pass.hash(&mut hashioka);
            let stored = hashioka.finish();
            let mut envy = OpenOptions::new()
                .append(true)    
                .open(".env")
                .expect("Didn't find an env file to send data through. Please create one!");
            writeln!(envy);
            writeln!(envy, "RUSTALYZER_PASSWORD={}", stored).expect("Env file failed");
            println!("Orginisations password has been set, remeber that now...!");
        },
        //logic to create a new password!
    }
    let vec: Vec<String> = env::args().collect();
    match vec[1].as_str() {
        "parse" => {
            match vec[2].as_str() {
                "filelist" => {
                    println!("This may take a while!");
                    let _ = task::block_on(livefile());
                    async fn livefile() -> io::Result<()> {
                        let privs = ["NT AUTHORITY\\SYSTEM",
                                    "Administrator",
                                    "admin",
                                    "DOMAIN\\Administrator",
                                    "SYSTEM",
                                    "root"];
                        println!("Analysing current system log files found.");
                        let nginx = Regex::new(r#"^(\S+) \S+ \S+ \[([^\]]+)\] \"(\S+) (.*?) (\S+)\" (\d{3}) (\d+) \"([^\"]*)\" \"([^\"]*)\""#).unwrap();
                        let apache = Regex::new(r#"^(\S+) (\S+) (\S+) \[([^\]]+)\] \"(\S+) (.*?) (\S+)\" (\d{3}) (\d+|-)$"#).unwrap();
                        let sissy = Regex::new(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}) (\S+) (\w+)(?:\[(\d+)\])?: (.+)$").unwrap();
                        let v2 = Regex::new(r"^<(\d+)>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s(.+)$").unwrap();
                        let authy = Regex::new(
                            r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<program>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
                        ).unwrap();
                        'goob: for pathing in SYSTEM_LOGS {
                            println!("{}", pathing);
                            let paf = pathing.to_string();
                            let syslog = match File::open(pathing) {
                                Ok(file) => file,
                                Err(err) => {
                                    error!("System file failed to open due to {}", err);
                                    continue 'goob;
                                }
                            };
                            let read = BufReader::new(syslog);
                            let path = Path::new(&paf);
                            match path.extension().and_then(|p| p.to_str()) {
                                Some("evtx") => {
                                    
                                    let mut user_attempts: Vec<DateTime<Utc>> = Vec::new();
                                    let mut parser = EvtxParser::from_path(path).unwrap(); // i know we werent met to do this but it was the only way
                                    for logy in parser.records_json() {
                                        let data = &logy.unwrap().data;
                                        let outcome: Result<Value, _> = serde_json::from_str(data);
                                        if let Ok(json) = outcome {
                                            
                                            let event = json["Event"]["System"]["EventID"].as_i64().unwrap_or(0);
                                            let command = json["Event"]["EventData"]["Data"].as_array()
                                            .and_then(|items| items.iter().find(|r| r["#attributes"]["Name"] == "CommandLine"))
                                            .and_then(|add| add["#text"].as_str())
                                            .unwrap_or("N/A");
                                            let address = json["Event"]["EventData"]["Data"]["#attributes"].as_array()
                                            .and_then(|items| items.iter().find(|r| r["#attributes"]["Name"] == "IpAddress"))
                                            .and_then(|add| add["#text"].as_str())
                                            .unwrap_or("N/A");
                                            let source = json["Event"]["System"]["Provider"]["#attributes"]["Name"].as_str().unwrap_or("");
                                            let pid = json["Event"]["System"]["Execution"]["#attributes"]["ProcessID"].as_u64().unwrap_or(0);
                                            let name = json["Event"]["EventData"]["Data"]["#attributes"].as_array()
                                            .and_then(|items| items.iter().find(|r| r["#attributes"]["Name"] == "SubjectName"))
                                            .and_then(|add| add["#text"].as_str())
                                            .unwrap_or("N/A");
                                            let sid = json["Event"]["System"]["Security"]["#attributes"]["UserID"].as_str().unwrap_or("Unknown ID");
                                            let time = json["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"].as_str().unwrap_or("");
                                            if event == 4688 && (command.to_lowercase().contains("powershell") || command.to_lowercase().contains("cmd.exe") || command.to_lowercase().contains(" -enc ")) {
                                                let message = format!("Unusual command activity launched: {} at {}", &command, &time);
                                                let _ = create_alert(&message);
                                            } else if event == 1102 || event == 104 {
                                                let message = format!("Audit log modified/cleared on the system by an actor at {}", time);
                                                let _ = create_alert(&message);
                                            } else if event == 1149 {
                                                let message = format!("A unauthorised remote access session was created, check if this was allowed at {}", time);
                                                let _ = create_alert(&message);
                                            } else if event == 4697 || event == 7045 {
                                                let message = format!("Unknown potentially malicious service installed or created on the machine at {}", time);
                                                let _ = create_alert(&message);
                                            } else if event == 4625 {
                                                if let Ok(timestamp) = DateTime::parse_from_str(time, "%Y-%m-%d %H:%M:%S") {
                                                    let timestamp_utc = timestamp.with_timezone(&Utc);
                                                    user_attempts.push(timestamp_utc);
                                                } else {
                                                    error!("Timestamp could not be parsed within the {} log file", &pathing)
                                                }
                                            } else if event == 4672 || event == 4624 {
                                                if sid == "S-1-5-18" || sid == "S-1-5-32-544" || privs.contains(&name) {
                                                    let message = format!("A potential priviledge escalation onto a adminstrative account has occured: {}", &time);
                                                    let _ = create_alert(&message);
                                                } else if !privs.contains(&name) {
                                                    let message = format!("A non root account was given special priviledges at this time: {}", &time);
                                                    let _ = create_alert(&message);
                                                }
                                            }
                                            let rt = Runtime::new().unwrap();
                                            let (nation, country) = rt.block_on(async {
                                                locate(address.to_string()).await
                                            });
                                            if nation {
                                                let message = format!("System accessed from a suspicious country: {}", &country);
                                                let _ = create_alert(&message);
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
                                        user_attempts.clear();
                                    }
                                    continue 'goob;
                                }
                                Some("log") | Some("syslog") | Some("messages") | Some("txt")=> {
                                    let mut user_attempts: Vec<DateTime<Utc>> = Vec::new();
                                    let agents = ["curl", "wget", "python", "scrapy", "httpclient"];
                                    let config = ["/etc", "/var/log", "/root", "/boot", "apt-key", "sources.list", "/backups/", "/db/", "/exports/", "/admin", "/.git", "/upload"];
                                    let actions = ["rm ", "mv ", "cp ", "nano ", "vim ", "echo ", "truncate ", "sudo ", "su "];
                                    let shell = ["nc", "curl", "wget", "bash -i", "python -c", "sh -c", "base64", "eval", "scp", "sftp", "rsync", "curl", "wget"];
                                    let patterns = ["/etc/passwd", "/var/www/", "../", "' OR 1=1 --", "UNION SELECT", "%27", "--", ";--", ";", "&&", "|", "%3B", "%26%26", "%7C", "'", "--", "UNION", "SELECT", " OR ", "DROP", "EXEC", "xp_cmdshell"];
                                    let extend = [".zip", ".sql", ".bak", ".7z", ".tar.gz", ".db"];
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
                                            
                                            let rt = Runtime::new().unwrap();
                                            let (nation, country) = rt.block_on(async {
                                                locate(log.ip).await
                                            });
                                            if nation {
                                                let message = format!("System accessed from a suspicious country: {}", &country);
                                                let _ = create_alert(&message);
                                            } 
                                            if log.url.to_lowercase().contains("login") || log.url.to_lowercase().contains("logon"){
                                                if let Ok(timestamp) = DateTime::parse_from_str(&log.time, "%Y-%m-%d %H:%M:%S") {
                                                    let timestamp_utc = timestamp.with_timezone(&Utc);
                                                    if timestamp_utc.hour() < 5 ||  timestamp_utc.hour() > 18{
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
                                                    error!("Timestamp could not be parsed within the {} log file", &pathing)
                                                }
                                            }
                                            let worker = log.agent.to_lowercase();
                                            if worker.trim().is_empty() || agents.iter().any(|a| worker.contains(a)) {
                                                let message = format!("Unusual user agent detected to access the site: {} at {}", &worker, &log.time);
                                                let _ = create_alert(&message);
                                            }
                                            if patterns.iter().any(|att| log.url.contains(att)) {
                                                let message = format!("A suspicious attack pattern attempt was detected within logs: {} at {}", &log.url ,&log.time);
                                                let _ = create_alert(&message);
                                            }
                                            for item in extend {
                                                if log.url.contains(item) || log.size > 10_000_000 {
                                                    let message = format!("Large file transfer of a suspicious nature detected at: {}, {}", &log.time, &log.url);
                                                    let _ = create_alert(&message);
                                                }
                                            }
                                            for method in &actions {
                                                if log.url.contains(method) {
                                                    for pattern in &config {
                                                        if log.url.contains(pattern) {
                                                            let message = format!("Attempted alteration or modification of important system files: {}, {}", &log.url, &log.time);
                                                            let _ = create_alert(&message);
                                                        }
                                                    }
                                                }
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
                                                if let Ok(timestamp) = DateTime::parse_from_str(&log.time, "%d/%b/%Y:%H:%M:%S %z") {
                                                    let timestamp_utc = timestamp.with_timezone(&Utc);
                                                    if timestamp_utc.hour() < 5 || timestamp_utc.hour() > 18{
                                                        println!("log");
                                                        let message = format!("Suspicious logon activity detected: {}", &log.time);
                                                        let _ = create_alert(&message);
                                                    }
                                                    if log.code == 401 || log.code == 403 {
                                                        user_attempts.push(timestamp_utc);
                                                    }

                                                } else {
                                                    error!("Timestamp could not be parsed within the {} log file", &pathing)
                                                }
                                            }

                                            for item in extend {
                                                if log.url.contains(item) || log.size > 10_000_000{
                                                    let message = format!("Large file transfer of a suspicious nature detected at: {}, {}", &log.time, &log.url);
                                                    let _ = create_alert(&message);
                                                }
                                            }
                                            
                                            let ip = log.ip.clone();
                                            let rt = Runtime::new().unwrap();
                                            let (nation, country) = rt.block_on(async {
                                                locate(ip).await
                                            });
                                            if nation {
                                                let message = format!("System accessed from a suspicious country: {}", &country);
                                                let _ = create_alert(&message);
                                            }

                                            for method in &actions {
                                                if log.url.contains(method) {
                                                    for pattern in &config {
                                                        if log.url.contains(pattern) {
                                                            let message = format!("Attempted alteration or modification of important system files: {}, {}", &log.url, &log.time);
                                                            let _ = create_alert(&message);
                                                        }
                                                    }
                                                }
                                            }
                                            if patterns.iter().any(|att| log.url.contains(att)) {
                                                let message = format!("A suspicious attack pattern attempt was detected within logs: {} at {}", &log.url, &log.time);
                                                let _ = create_alert(&message);
                                            }   
                                        } else if let Some(crapola) = &sissy.captures(&analysed_line) {
                                            println!("Caught!");
                                            let log = SysLog {
                                                priority: 0,
                                                timestamp: crapola.get(1).unwrap().as_str().to_string(),
                                                hostname: crapola.get(2).unwrap().as_str().to_string(),
                                                program: crapola.get(3).unwrap().as_str().to_string(),
                                                pid: crapola.get(4).unwrap().as_str().parse().unwrap_or(0),
                                                message: crapola.get(5).unwrap().as_str().to_string(),
                                            };
                                            if log.program == "sshd" || log.program == "ssh" {
                                                println!("I caught a bad logon attempt");
                                                if let Ok(timestamp) = DateTime::parse_from_str(&log.timestamp, "%d/%b/%Y:%H:%M:%S %z") {
                                                    println!("date parsed");
                                                    let timestamp_utc = timestamp.with_timezone(&Utc);
                                                    if timestamp_utc.hour() < 5 ||  timestamp_utc.hour() > 18 {
                                                        println!("log");
                                                        let message = format!("Suspicious logon activity detected: {}", &log.timestamp);
                                                        let _ = create_alert(&message);
                                                    }
                                                    if log.message.to_lowercase().contains("Failed Password") {
                                                        user_attempts.push(timestamp_utc);
                                                    }

                                                } else {
                                                    error!("Timestamp could not be parsed within the {} log file", &pathing)
                                                }
                                            }
                                            if let Some(ip) = extract_ip(&log.message) {
                                                let rt = Runtime::new().unwrap();
                                                let (nation, country) = rt.block_on(async {
                                                    locate(ip).await
                                                });
                                                if nation {
                                                    let message = format!("System accessed from a suspicious country: {}", &country);
                                                    let _ = create_alert(&message);
                                                }
                                            } 

                                            if shell.iter().any(|r| log.message.contains(r)) {
                                                let message = format!("Reverse shell OR suspicious file activity has been detected!: {}, {}", &log.message, &log.timestamp);
                                                 _ = create_alert(&message);
                                            }
                                            for method in &actions {
                                                if log.message.contains(method) {
                                                    for pattern in &config {
                                                        if log.message.contains(pattern) {
                                                            let message = format!("Attempted alteration or modification of important system files: {}, {}", &log.message, &log.timestamp);
                                                            let _ = create_alert(&message);
                                                        }
                                                    }
                                                }
                                            }
                                            

                                            for pattern in &patterns {
                                                if log.message.contains(pattern) {
                                                    let message = format!("Attempted suspicious pattern attempted!, {} {}", &log.message, &log.timestamp);
                                                    let _ = create_alert(&message);
                                                }
                                            }

                                        } else if let Some(crapola) = &v2.captures(&analysed_line){
                                            println!("Caught!");
                                            let log = SysLog {
                                                priority: crapola.get(1).and_then(|m| m.as_str().parse::<i32>().ok()).unwrap_or(0),
                                                timestamp: crapola.get(2).unwrap().as_str().to_string(),
                                                hostname: crapola.get(3).unwrap().as_str().to_string(),
                                                program: crapola.get(4).unwrap().as_str().to_string(),
                                                pid: crapola.get(6).and_then(|o| o.as_str().parse::<i32>().ok()).unwrap_or(0),
                                                message: crapola.get(5).unwrap().as_str().to_string(),
                                            };
                                            if log.program == "sshd" || log.program == "ssh" {
                                                if let Ok(timestamp) = DateTime::parse_from_str(&log.timestamp, "%d/%b/%Y:%H:%M:%S %z") {
                                                    println!("date parsed");
                                                    let timestamp_utc = timestamp.with_timezone(&Utc);
                                                    if timestamp_utc.hour() < 5 ||  timestamp_utc.hour() > 18 {
                                                        println!("log");
                                                        if log.message.to_lowercase().contains("session opened") {
                                                            let message = format!("Suspicious logon activity detected: {}", &log.timestamp);
                                                            let _ = create_alert(&message);
                                                        }
                                                    }
                                                    if log.message.to_lowercase().contains("Failed Password") {
                                                        println!("Code");
                                                        user_attempts.push(timestamp_utc);
                                                    }

                                                } else {
                                                    error!("Timestamp could not be parsed within the {} log file", &pathing)
                                                }
                                            }
                                            if let Some(ip) = extract_ip(&log.message) {
                                                let rt = Runtime::new().unwrap();
                                                let (nation, country) = rt.block_on(async {
                                                    locate(ip).await
                                                });
                                                if nation {
                                                    let message = format!("System accessed from a suspicious country: {}", &country);
                                                    let _ = create_alert(&message);
                                                }
                                            } 
                                            if log.program == "sudo" || log.program == "su" {
                                                for method in &actions {
                                                    if log.message.contains(method) {
                                                        for pattern in &config {
                                                            if log.message.contains(pattern) {
                                                                let message = format!("Attempted alteration or modification of important system files: {}, {}", &log.message, &log.timestamp);
                                                                let _ = create_alert(&message);
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            if shell.iter().any(|r| log.message.contains(r)) {
                                                let message = format!("Reverse shell OR suspicious file activity has been detected!: {}, {}", &log.message, &log.timestamp);
                                                 _ = create_alert(&message);
                                            }

                                            for pattern in &patterns {
                                                if log.message.contains(pattern) {
                                                    let message = format!("Attempted suspicious pattern attempted!, {} {}", &log.message, &log.timestamp);
                                                    let _ = create_alert(&message);
                                                }
                                            }
                                        } else if let Some(crapola) = &authy.captures(&analysed_line){
                                            let log = Auth {
                                                timestamp: crapola.name("timestamp").unwrap().as_str().to_string(),
                                                host: crapola.name("host").unwrap().as_str().to_string(),
                                                program: crapola.name("program").unwrap().as_str().to_string(),
                                                pid: crapola.name("pid").and_then(|z| z.as_str().parse::<i32>().ok()).unwrap_or(0),
                                                message: crapola.name("message").unwrap().as_str().to_string(),
                                            };

                                            let ip = log.host.trim_start_matches("ip-").replace("-", ".");
                                            let rt = Runtime::new().unwrap();
                                            let (nation, country) = rt.block_on(async {
                                                locate(ip).await
                                            });
                                            if nation {
                                                let message = format!("System accessed from a suspicious country: {}", &country);
                                                let _ = create_alert(&message);
                                            }

                                            if log.program == "sshd" || log.program == "ssh" {
                                                if let Ok(timestamp) = DateTime::parse_from_str(&log.timestamp, "%d/%b/%Y:%H:%M:%S %z") {
                                                    println!("date parsed");
                                                    let timestamp_utc = timestamp.with_timezone(&Utc);
                                                    if timestamp_utc.hour() < 5 ||  timestamp_utc.hour() > 18 {
                                                        println!("log");
                                                        if log.message.to_lowercase().contains("session opened") || log.message.to_lowercase().contains("accepted password"){
                                                            let message = format!("Suspicious logon activity detected: {}", &log.timestamp);
                                                            let _ = create_alert(&message);
                                                        } else if log.message.to_lowercase().contains("session opened ") && log.message.to_lowercase().contains("session opened ") {
                                                            let message = format!("Root priviledge accessed, check this was allowed: {}", &log.timestamp);
                                                            let _ = create_alert(&message);
                                                        }
                                                    }
                                                    if log.message.to_lowercase().contains("failed password") {
                                                        println!("Code");
                                                        user_attempts.push(timestamp_utc);
                                                    }

                                                }  else {
                                                    error!("Timestamp could not be parsed within the {} log file", &pathing)
                                                }
                                            }
                                            if log.program == "sudo" || log.program == "su" {
                                                for method in &actions {
                                                    if log.message.contains(method) {
                                                        for pattern in &config {
                                                            if log.message.contains(pattern) {
                                                                let message = format!("Attempted alteration or modification of important system files: {}, {}", &log.message, &log.timestamp);
                                                                let _ = create_alert(&message);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            for pattern in &patterns {
                                                if log.message.contains(pattern) {
                                                    let message = format!("Attempted suspicious pattern attempted!, {} {}", &log.message, &log.timestamp);
                                                    let _ = create_alert(&message);
                                                }
                                            }
                                        } else {
                                            error!("Unrecognise file format {}", &pathing);
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
                                    user_attempts.clear();
                                    info!("Scan of filename {} has been completed", &pathing);
                                    continue 'goob;
                                }
                                _ => {
                                    eprintln!("Unsupported file extension for file: {}", &pathing);
                                }
                            }
                            return Ok(())
                        }
                        return Ok(());
                    }  
                }
            _ => {
                eprintln!("Unsupported file");
            }
            }
        }
        "export" => {
            match vec[2].as_str() {
                "csv" => {
                    let log_file = match File::open(vec[3].as_str()) {
                        Ok(f1) => f1,
                        Err(e1) => {
                            eprintln!("Failed to create file: {}", e1);
                            return;
                        }
                    };
                    let reader = BufReader::new(log_file);
                    let output = match File::create("results.csv") {
                        Ok(f) => f,
                        Err(e) => {
                            eprintln!("Failed to create file: {}", e);
                            return;
                        }
                    };
                    let path = Path::new(vec[3].as_str());
                    match path.extension().and_then(|s| s.to_str()) {
                        Some("evtx") => {
                            let line1 = "ip,timestamp,source,EventID,pid,sid,Subject Name,Command Entered";
                            let _ = export_file(&output, line1);
                            let mut parser = EvtxParser::from_path(path).unwrap();
                            for logy in parser.records_json() {
                                let data = &logy.unwrap().data;
                                let result: Result<Value, _> = serde_json::from_str(data);
                                if let Ok(json) = result {
                                    let event = json["Event"]["System"]["EventID"].as_i64().unwrap_or(0);
                                    let command = json["Event"]["EventData"]["Data"].as_array()
                                    .and_then(|items| items.iter().find(|r| r["#attributes"]["Name"] == "CommandLine"))
                                    .and_then(|add| add["#text"].as_str())
                                    .unwrap_or("N/A");
                                    let address = json["Event"]["EventData"]["Data"]["#attributes"].as_array()
                                    .and_then(|items| items.iter().find(|r| r["#attributes"]["Name"] == "IpAddress"))
                                    .and_then(|add| add["#text"].as_str())
                                    .unwrap_or("N/A");
                                    let time = json["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"].as_str().unwrap_or("");
                                    let source = json["Event"]["System"]["Provider"]["#attributes"]["Name"].as_str().unwrap_or("");
                                    let pid = json["Event"]["System"]["Execution"]["#attributes"]["ProcessID"].as_u64().unwrap_or(0);
                                    let name = json["Event"]["EventData"]["Data"]["#attributes"].as_array()
                                    .and_then(|items| items.iter().find(|r| r["#attributes"]["Name"] == "SubjectName"))
                                    .and_then(|add| add["#text"].as_str())
                                    .unwrap_or("N/A");
                                    let sid = json["Event"]["System"]["Security"]["#attributes"]["UserID"].as_str().unwrap_or("Unknown ID");
                                    let line = format!(r#"{{"ip": "{}", "timestamp": "{}", "source": "{}", "EventID": {}, "pid": {}, "sid": {}, "Subject Name": {}, "Command Entered": {}}}"#, address, time, source, event, pid, sid, name, command);
                                    let _ = export_file(&output, &line);
                                }
                            }
                        }

                        Some("log") => {
                            let authy = Regex::new(
                                r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<program>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
                            ).unwrap();
                            let nginx = Regex::new(r#"^(\S+) \S+ \S+ \[([^\]]+)\] \"(\S+) (.*?) (\S+)\" (\d{3}) (\d+) \"([^\"]*)\" \"([^\"]*)\""#).unwrap();
                            let apache = Regex::new(r#"^(\S+) (\S+) (\S+) \[([^\]]+)\] \"(\S+) (.*?) (\S+)\" (\d{3}) (\d+|-)$"#).unwrap();
                            let sissy = Regex::new(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}) (\S+) (\w+)(?:\[(\d+)\])?: (.+)$").unwrap();
                            let v2 = Regex::new(r"^<(\d+)>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s(.+)$").unwrap();
                            let line1 = "ip,time,method,url,protocol,code,size,referer,useragent";
                            let _ = export_file(&output, line1);
                            for lin in reader.lines() {
                                let analysed_line = if let Ok(line) = lin {
                                    line
                                } else {
                                    continue; 
                                };
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
                                    let line = format!("{},{},{},{},{},{},{},{},{}", log.ip, log.time, log.method, log.url, log.protocol, log.code, log.size, log.refer, log.agent);
                                    let _ = export_file(&output, &line);

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
                                    let line = format!("{},{},{},{},{},{},{},{}", log.ip, log.time, log.http, log.url, log.version, log.code, log.size, log.user);
                                    let _ = export_file(&output, &line);
                                } else if let Some(crapola) = &sissy.captures(&analysed_line) {
                                    println!("Caught!");
                                    let log = SysLog {
                                        priority: crapola.get(6).and_then(|m| m.as_str().parse::<i32>().ok()).unwrap_or(0),
                                        timestamp: crapola.get(1).unwrap().as_str().to_string(),
                                        hostname: crapola.get(2).unwrap().as_str().to_string(),
                                        program: crapola.get(3).unwrap().as_str().to_string(),
                                        pid: crapola.get(4).unwrap().as_str().parse().unwrap_or(0),
                                        message: crapola.get(5).unwrap().as_str().to_string(),
                                    };
                                    let line = format!("{},{},{},{},{},{},{},{}", "N/A", log.timestamp, log.program, log.message, log.priority, log.pid, "N/A", log.hostname);
                                    let _ = export_file(&output, &line);
                                } else if let Some(crapola) = &v2.captures(&analysed_line){
                                    println!("Caught!");
                                    let log = SysLog {
                                        priority: crapola.get(1).and_then(|m| m.as_str().parse::<i32>().ok()).unwrap_or(0),
                                        timestamp: crapola.get(2).unwrap().as_str().to_string(),
                                        hostname: crapola.get(3).unwrap().as_str().to_string(),
                                        program: crapola.get(4).unwrap().as_str().to_string(),
                                        pid: crapola.get(6).and_then(|o| o.as_str().parse::<i32>().ok()).unwrap_or(0),
                                        message: crapola.get(5).unwrap().as_str().to_string(),
                                    };
                                    let line = format!("{},{},{},{},{},{},{},{}", "N/A", log.timestamp, log.program, log.message, log.priority, log.pid, "N/A", log.hostname);
                                    let _ = export_file(&output, &line);
                                };
                            }
                        }
                        _ => println!("Issues"),
                    }
                },
                "json" => {
                    let log_file = match File::open(vec[3].as_str()) {
                        Ok(f1) => f1,
                        Err(e1) => {
                            eprintln!("Failed to create file: {}", e1);
                            return;
                        }
                    };
                    let reader = BufReader::new(log_file);
                    let output = match File::create("output.json") {
                        Ok(f) => f,
                        Err(e) => {
                            eprintln!("Failed to create file: {}", e);
                            return;
                        }
                    };
                    let path = Path::new(vec[3].as_str());
                    match path.extension().and_then(|s| s.to_str()) {
                        Some("evtx") => {
                            let mut parser = EvtxParser::from_path(path).unwrap();
                            for logy in parser.records_json() {
                                let data = &logy.unwrap().data;
                                let result: Result<Value, _> = serde_json::from_str(data);
                                if let Ok(js) = result {
                                    let event = js["Event"]["System"]["EventID"].as_i64().unwrap_or(0);
                                    let command = js["Event"]["EventData"]["Data"].as_array()
                                    .and_then(|items| items.iter().find(|r| r["#attributes"]["Name"] == "CommandLine"))
                                    .and_then(|add| add["#text"].as_str())
                                    .unwrap_or("N/A");
                                    let address = js["Event"]["EventData"]["Data"]["#attributes"].as_array()
                                    .and_then(|items| items.iter().find(|r| r["#attributes"]["Name"] == "IpAddress"))
                                    .and_then(|add| add["#text"].as_str())
                                    .unwrap_or("N/A");
                                    let time = js["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"].as_str().unwrap_or("");
                                    let source = js["Event"]["System"]["Provider"]["#attributes"]["Name"].as_str().unwrap_or("");
                                    let pid = js["Event"]["System"]["Execution"]["#attributes"]["ProcessID"].as_u64().unwrap_or(0);
                                    let name = js["Event"]["EventData"]["Data"]["#attributes"].as_array()
                                    .and_then(|items| items.iter().find(|r| r["#attributes"]["Name"] == "SubjectName"))
                                    .and_then(|add| add["#text"].as_str())
                                    .unwrap_or("N/A");
                                    let sid = js["Event"]["System"]["Security"]["#attributes"]["UserID"].as_str().unwrap_or("Unknown ID");
                                    let line = format!(r#"{{"ip": "{}", "timestamp": "{}", "source": "{}", "EventID": {}, "pid": {}, "sid": {}, "Subject Name": {}, "Command Entered": {}}}"#, address, time, source, event, pid, sid, name, command);
                                    let _ = export_file(&output, &line);
                                }
                            }
                        }
                        Some("log") => {
                            let authy = Regex::new(
                                r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<program>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
                            ).unwrap();
                            let nginx = Regex::new(r#"^(\S+) \S+ \S+ \[([^\]]+)\] \"(\S+) (.*?) (\S+)\" (\d{3}) (\d+) \"([^\"]*)\" \"([^\"]*)\""#).unwrap();
                            let apache = Regex::new(r#"^(\S+) (\S+) (\S+) \[([^\]]+)\] \"(\S+) (.*?) (\S+)\" (\d{3}) (\d+|-)$"#).unwrap();
                            let sissy = Regex::new(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}) (\S+) (\w+)(?:\[(\d+)\])?: (.+)$").unwrap();
                            let v2 = Regex::new(r"^<(\d+)>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s(.+)$").unwrap();
                            for lin in reader.lines() {
                                let analysed_line = if let Ok(line) = lin {
                                    line
                                } else {
                                    continue; 
                                };
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
                                    let line = format!(r#"{{"ip": "{}", "timestamp": "{}", "method": "{}", "url": "{}", "protocol": {}, "code": {}, "size": {}, "referer": {}, "useragent": {}}}"#, log.ip, log.time, log.method, log.url, log.protocol, log.code, log.size, log.refer, log.agent);
                                    let _ = export_file(&output, &line);

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
                                    let line = format!(r#"{{"ip": "{}", "timestamp": "{}", "url": "{}", "protocol": {}, "code": {}, "size": {}, "referer": {}, "useragent": {}}}"#, log.ip, log.time, log.url, log.http, log.code, log.size, log.version, log.user);
                                    let _ = export_file(&output, &line);
                                } else if let Some(crapola) = &sissy.captures(&analysed_line) {
                                    println!("Caught!");
                                    let log = SysLog {
                                        priority: crapola.get(6).and_then(|m| m.as_str().parse::<i32>().ok()).unwrap_or(0),
                                        timestamp: crapola.get(1).unwrap().as_str().to_string(),
                                        hostname: crapola.get(2).unwrap().as_str().to_string(),
                                        program: crapola.get(3).unwrap().as_str().to_string(),
                                        pid: crapola.get(4).unwrap().as_str().parse().unwrap_or(0),
                                        message: crapola.get(5).unwrap().as_str().to_string(),
                                    };
                                    let line = format!("{},{},{},{},{},{},{},{}", "N/A", log.timestamp, log.program, log.message, log.priority, log.pid, "N/A", log.hostname);
                                    let _ = export_file(&output, &line);
                                } else if let Some(crapola) = &v2.captures(&analysed_line){
                                    println!("Caught!");
                                    let log = SysLog {
                                        priority: crapola.get(1).and_then(|m| m.as_str().parse::<i32>().ok()).unwrap_or(0),
                                        timestamp: crapola.get(2).unwrap().as_str().to_string(),
                                        hostname: crapola.get(3).unwrap().as_str().to_string(),
                                        program: crapola.get(4).unwrap().as_str().to_string(),
                                        pid: crapola.get(6).and_then(|o| o.as_str().parse::<i32>().ok()).unwrap_or(0),
                                        message: crapola.get(5).unwrap().as_str().to_string(),
                                    };
                                    let line = format!("{},{},{},{},{},{},{},{}", "N/A", log.timestamp, log.program, log.message, log.priority, log.pid, "N/A", log.hostname);
                                    let _ = export_file(&output, &line);
                                
                                } else if let Some(crapola) = &authy.captures(&analysed_line){
                                    let log = Auth {
                                        timestamp: crapola.name("timestamp").unwrap().as_str().to_string(),
                                        host: crapola.name("host").unwrap().as_str().to_string(),
                                        program: crapola.name("program").unwrap().as_str().to_string(),
                                        pid: crapola.name("pid").and_then(|z| z.as_str().parse::<i32>().ok()).unwrap_or(0),
                                        message: crapola.name("message").unwrap().as_str().to_string(),
                                    };
                                    let line = format!("{},{},{},{},{},{},{},{}", "N/A", log.timestamp, log.program, log.message, "N/A", log.pid, "N/A", log.host);
                                    let _ = export_file(&output, &line);
                                }
                                
                        }   }
                        _ => error!("User attempted to process a log extension not recognised by the program {:?} ", path.extension()),
                    }
                },
                _ => {
                    eprintln!("Unrecognised format, exiting...");
                    error!("User attempted to process a log extension not recognised by the program");
                }
            }
            
        },
        "help" => {
            println!("How to use this tool:


                First of all ensure rust is installed and running on your computer, for a full guide: https://www.rust-lang.org/tools/install,
                Then use cargo to use 'cargo run' and then you have options for the tool:

                    parse -> Read and analyse files for behavioural patterns.
                        filelist -> Read the list of files that exist to be searched for.
                    
                    export -> Convert a log file to a specific data storage format to take backups.
                        csv -> Convert to a comma seperated values file with headers.
                        json -> Convert to a JSON object file containing the log data.
                            After these options list the file/file path of the file you want to export and it should work!
                    
                    help -> This tells you the list of commands and features you can run
                

            SETTINGS:
            To modify the use of this tool control-f within the code editor for the email const, 
            this allows you to set up your email to recieve alerts when behavioural patterns are detected within the logs that might be on interest.

            To modify the files it's scanning for control-f to system_logs vector list and add in additional file values/paths.


            ")
        }
        _ => println!("Exiting...")
    }
}


fn create_alert(message: &str) -> std::result::Result<(), Box<dyn std::error::Error>>{
    dotenv().ok();  
    let messagestring = Message::builder().from("rustalyzer@gmail.com".parse()?).to(EMAIL.parse().unwrap()).subject("Security Alert from logs").body(message.to_string()).unwrap();
    let key = env::var("API_KEY").unwrap();
    let keys = Credentials::new(
        "apikey".to_string(),
        key,
    );
    let mailer = SmtpTransport::starttls_relay("smtp.sendgrid.net")? 
        .credentials(keys)
        .build();
    match mailer.send(&messagestring) {
        Ok(_) => println!("Email sent to {} concerning a security flaw {}", &EMAIL, &message),
        Err(e) => eprintln!("Error processing email! {}", e),
    }
    
    Ok(())
}

async fn locate(ip: String) -> (bool, String) {
    let service = Service::IpApi;
    let allowed = ["united kingdom","united states of america"];
    let protocol = match Locator::get(&ip, service).await {
        Ok(protocol) => protocol,
        Err(error) => {
            error!("Geolocating IP address for log produced an error on this ip {}", &ip);
            return (false, false.to_string());
        }
    };
    println!("{}", &protocol.country);
    if !allowed.contains(&protocol.country.to_lowercase().as_str()) {
        return (true, protocol.country.to_string());
    } else {
        return (false, false.to_string());
    }
    
}

fn export_file (mut files: &File, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(files, "{}", message)?;
    Ok(())
}

fn extract_ip(msg: &str) ->  Option<String>{
    let ipfinder = Regex::new(r"\b(\d{1,3}\.){3}\d{1,3}\b").unwrap(); //looked online for this
    ipfinder.find(msg).map(|r| r.as_str().to_string())
}