// ═══════════════════════════════════════════════════════════════════════
//  Payload Registry — Maps categories to verified GitHub raw URLs
//  All URLs verified against actual repository tree structures.
//  SecLists: github.com/danielmiessler/SecLists (branch: master)
//  PATT: github.com/swisskyrepo/PayloadsAllTheThings (branch: master)
// ═══════════════════════════════════════════════════════════════════════

const SL: &str = "https://raw.githubusercontent.com/danielmiessler/SecLists/master";
const PT: &str = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master";

/// A single downloadable payload file
#[derive(Debug, Clone)]
pub struct PayloadSource {
    pub source_name: String,
    pub category: String,
    pub filename: String,
    pub url: String,
    pub description: String,
}

/// All known categories
pub fn all_categories() -> Vec<String> {
    vec![
        "sqli".into(),
        "xss".into(),
        "cmdi".into(),
        "ssti".into(),
        "lfi".into(),
        "ssrf".into(),
        "xxe".into(),
        "ldap".into(),
        "nosql".into(),
        "open_redirect".into(),
        "auth".into(),
        "fuzzing".into(),
        "traversal".into(),
    ]
}

/// Get download sources for a given category
pub fn sources_for(category: &str) -> Vec<PayloadSource> {
    match category {
        // ─── SQL Injection ─────────────────────────────────────────
        "sqli" => vec![
            // PayloadsAllTheThings — verified paths
            sl("sqli", "sqli-auth-bypass.txt",      "SQL Injection/Intruder/Auth_Bypass.txt",       "SQLi authentication bypass"),
            sl("sqli", "sqli-auth-bypass2.txt",      "SQL Injection/Intruder/Auth_Bypass2.txt",      "SQLi auth bypass variant 2"),
            sl("sqli", "sqli-error-based.txt",       "SQL Injection/Intruder/Generic_ErrorBased.txt","Error-based SQL injection"),
            sl("sqli", "sqli-union-select.txt",      "SQL Injection/Intruder/Generic_UnionSelect.txt","UNION SELECT payloads"),
            sl("sqli", "sqli-time-based.txt",        "SQL Injection/Intruder/Generic_TimeBased.txt", "Time-based blind SQLi"),
            sl("sqli", "sqli-generic-fuzz.txt",      "SQL Injection/Intruder/Generic_Fuzz.txt",      "Generic SQL fuzzing"),
            sl("sqli", "sqli-polyglots.txt",         "SQL Injection/Intruder/SQLi_Polyglots.txt",    "SQLi polyglot payloads"),
            sl("sqli", "sqli-mysql-fuzzdb.txt",      "SQL Injection/Intruder/FUZZDB_MYSQL.txt",      "MySQL-specific payloads"),
            sl("sqli", "sqli-mysql-time.txt",        "SQL Injection/Intruder/FUZZDB_MySQL-WHERE_Time.txt", "MySQL time-based"),
            sl("sqli", "sqli-mysql-readfile.txt",    "SQL Injection/Intruder/FUZZDB_MySQL_ReadLocalFiles.txt", "MySQL file read"),
            sl("sqli", "sqli-mssql-fuzzdb.txt",      "SQL Injection/Intruder/FUZZDB_MSSQL.txt",      "MSSQL-specific payloads"),
            sl("sqli", "sqli-mssql-enum.txt",        "SQL Injection/Intruder/FUZZDB_MSSQL_Enumeration.txt", "MSSQL enumeration"),
            sl("sqli", "sqli-mssql-time.txt",        "SQL Injection/Intruder/FUZZDB_MSSQL-WHERE_Time.txt", "MSSQL time-based"),
            sl("sqli", "sqli-oracle-fuzzdb.txt",     "SQL Injection/Intruder/FUZZDB_Oracle.txt",     "Oracle-specific payloads"),
            sl("sqli", "sqli-postgres-enum.txt",     "SQL Injection/Intruder/FUZZDB_Postgres_Enumeration.txt", "PostgreSQL enum"),
            // SecLists — login bypass
            sec("sqli", "sqli-login-bypass.txt",  "Fuzzing/login_bypass.txt",                    "Login bypass payloads"),
        ],

        // ─── Cross-Site Scripting ──────────────────────────────────
        "xss" => vec![
            // SecLists — human-friendly XSS
            sec("xss", "xss-portswigger.txt",     "Fuzzing/XSS/human-friendly/XSS-Cheat-Sheet-PortSwigger.txt", "PortSwigger XSS cheat sheet"),
            sec("xss", "xss-jhaddix.txt",          "Fuzzing/XSS/human-friendly/XSS-Jhaddix.txt",   "Jhaddix XSS payloads"),
            sec("xss", "xss-brutelogic.txt",       "Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt","BruteLogic XSS payloads"),
            sec("xss", "xss-rsnake.txt",            "Fuzzing/XSS/human-friendly/XSS-RSNAKE.txt",    "RSNAKE XSS payloads"),
            sec("xss", "xss-somdev.txt",            "Fuzzing/XSS/human-friendly/XSS-Somdev.txt",    "Somdev XSS payloads"),
            sec("xss", "xss-ofjaaah.txt",           "Fuzzing/XSS/human-friendly/XSS-OFJAAAH.txt",   "OFJAAAH XSS payloads"),
            sec("xss", "xss-payloadbox.txt",        "Fuzzing/XSS/human-friendly/XSS-payloadbox.txt","payloadbox XSS"),
            sec("xss", "xss-vectors-mario.txt",     "Fuzzing/XSS/human-friendly/XSS-Vectors-Mario.txt", "Mario XSS vectors"),
            sec("xss", "xss-bypass.txt",            "Fuzzing/XSS/human-friendly/XSS-Bypass-Strings-BruteLogic.txt", "XSS bypass strings"),
            sec("xss", "xss-context-jhaddix.txt",   "Fuzzing/XSS/human-friendly/XSS-With-Context-Jhaddix.txt", "XSS with context"),
            sec("xss", "xss-no-parens.txt",         "Fuzzing/XSS/human-friendly/xss-without-parentheses-semi-colons-portswigger.txt", "XSS without parens"),
            // SecLists — robot-friendly XSS
            sec("xss", "xss-robot-jhaddix.txt",     "Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt",   "Robot-friendly Jhaddix"),
            sec("xss", "xss-robot-fuzzing.txt",      "Fuzzing/XSS/robot-friendly/XSS-Fuzzing.txt",   "Robot-friendly XSS fuzzing"),
            // SecLists — Polyglots
            sec("xss", "xss-polyglots.txt",          "Fuzzing/XSS/Polyglots/XSS-Polyglots.txt",      "XSS polyglots"),
            sec("xss", "xss-polyglot-0xsobky.txt",   "Fuzzing/XSS/Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt", "Ultimate polyglot"),
            // PayloadsAllTheThings
            sl("xss", "xss-patt-alert.txt",          "XSS Injection/Intruders/xss_alert.txt",        "PATT XSS alert payloads"),
            sl("xss", "xss-patt-identifiable.txt",   "XSS Injection/Intruders/xss_alert_identifiable.txt", "Identifiable XSS"),
            sl("xss", "xss-patt-quick.txt",           "XSS Injection/Intruders/xss_payloads_quick.txt", "Quick XSS payloads"),
            sl("xss", "xss-patt-polyglots.txt",       "XSS Injection/Intruders/XSS_Polyglots.txt",    "PATT XSS polyglots"),
            sl("xss", "xss-patt-brutelogic.txt",      "XSS Injection/Intruders/BRUTELOGIC-XSS-STRINGS.txt", "BruteLogic strings"),
            sl("xss", "xss-patt-jhaddix.txt",         "XSS Injection/Intruders/JHADDIX_XSS.txt",      "PATT Jhaddix XSS"),
            sl("xss", "xss-patt-detection.txt",       "XSS Injection/Intruders/XSSDetection.txt",     "XSS detection payloads"),
            sl("xss", "xss-patt-event-handlers.txt",  "XSS Injection/Intruders/0xcela_event_handlers.txt", "Event handler XSS"),
            sl("xss", "xss-patt-mario.txt",            "XSS Injection/Intruders/MarioXSSVectors.txt",  "Mario XSS vectors"),
        ],

        // ─── Command Injection ─────────────────────────────────────
        "cmdi" => vec![
            sec("cmdi", "cmdi-commix.txt",           "Fuzzing/command-injection-commix.txt",          "Commix command injection"),
            sec("cmdi", "cmdi-unix-attacks.txt",      "Fuzzing/UnixAttacks.fuzzdb.txt",               "Unix attack payloads"),
            sec("cmdi", "cmdi-windows-attacks.txt",   "Fuzzing/Windows-Attacks.fuzzdb.txt",            "Windows attack payloads"),
            sl("cmdi", "cmdi-exec-unix.txt",           "Command Injection/Intruder/command-execution-unix.txt", "Unix command exec"),
            sl("cmdi", "cmdi-exec.txt",                 "Command Injection/Intruder/command_exec.txt",  "General command exec"),
        ],

        // ─── Server-Side Template Injection ────────────────────────
        "ssti" => vec![
            sec("ssti", "ssti-expressions.txt",       "Fuzzing/template-engines-expression.txt",       "Template engine expressions"),
            sec("ssti", "ssti-special-vars.txt",       "Fuzzing/template-engines-special-vars.txt",     "Template special variables"),
            sec("ssti", "ssti-ssi-injection.txt",      "Fuzzing/SSI-Injection-Jhaddix.txt",             "SSI injection payloads"),
        ],

        // ─── Local File Inclusion ──────────────────────────────────
        "lfi" => vec![
            // SecLists — LFI directory
            sec("lfi", "lfi-jhaddix.txt",              "Fuzzing/LFI/LFI-Jhaddix.txt",                  "Jhaddix LFI payloads"),
            // PayloadsAllTheThings — File Inclusion
            sl("lfi", "lfi-traversal.txt",             "File Inclusion/Intruders/Traversal.txt",        "Path traversal payloads"),
            sl("lfi", "lfi-linux-files.txt",           "File Inclusion/Intruders/Linux-files.txt",      "Linux system files"),
            sl("lfi", "lfi-windows-files.txt",         "File Inclusion/Intruders/Windows-files.txt",    "Windows system files"),
            sl("lfi", "lfi-bsd-files.txt",             "File Inclusion/Intruders/BSD-files.txt",        "BSD system files"),
            sl("lfi", "lfi-mac-files.txt",             "File Inclusion/Intruders/Mac-files.txt",        "macOS system files"),
            sl("lfi", "lfi-web-files.txt",             "File Inclusion/Intruders/Web-files.txt",        "Web config files"),
            sl("lfi", "lfi-simple-check.txt",          "File Inclusion/Intruders/simple-check.txt",     "Simple LFI checks"),
            sl("lfi", "lfi-fd-check.txt",              "File Inclusion/Intruders/LFI-FD-check.txt",     "File descriptor check"),
            sl("lfi", "lfi-windows-check.txt",         "File Inclusion/Intruders/LFI-WindowsFileCheck.txt", "Windows LFI check"),
            sl("lfi", "lfi-dotslash.txt",              "File Inclusion/Intruders/dot-slash-PathTraversal_and_LFI_pairing.txt", "Dotslash traversal"),
            sl("lfi", "lfi-file-list.txt",             "File Inclusion/Intruders/List_Of_File_To_Include.txt", "Files to include"),
            sl("lfi", "lfi-nullbyte.txt",              "File Inclusion/Intruders/List_Of_File_To_Include_NullByteAdded.txt", "Null byte LFI"),
            sl("lfi", "lfi-php-filter.txt",            "File Inclusion/Intruders/php-filter-iconv.txt", "PHP filter iconv"),
        ],

        // ─── SSRF ──────────────────────────────────────────────────
        "ssrf" => vec![
            sec("ssrf", "ssrf-uri-xss.txt",            "Fuzzing/URI-XSS.fuzzdb.txt",                   "URI-based payloads"),
            sec("ssrf", "ssrf-curl-protocols.txt",     "Fuzzing/curl-protocols.txt",                    "Curl protocol payloads"),
        ],

        // ─── XXE ──────────────────────────────────────────────────
        "xxe" => vec![
            sec("xxe", "xxe-fuzzing.txt",              "Fuzzing/XXE-Fuzzing.txt",                       "XXE fuzzing payloads"),
            sec("xxe", "xxe-xml-fuzz.txt",             "Fuzzing/XML-FUZZ.txt",                          "XML fuzzing payloads"),
            sl("xxe", "xxe-patt-fuzzing.txt",          "XXE Injection/Intruders/XXE_Fuzzing.txt",       "PATT XXE fuzzing"),
            sl("xxe", "xxe-xml-attacks.txt",           "XXE Injection/Intruders/xml-attacks.txt",       "XML attack payloads"),
        ],

        // ─── Directory Traversal ───────────────────────────────────
        "traversal" => vec![
            sl("traversal", "traversal-deep.txt",      "Directory Traversal/Intruder/deep_traversal.txt", "Deep traversal"),
            sl("traversal", "traversal-basic.txt",     "Directory Traversal/Intruder/directory_traversal.txt", "Basic traversal"),
            sl("traversal", "traversal-dotdotpwn.txt", "Directory Traversal/Intruder/dotdotpwn.txt",    "DotDotPwn payloads"),
            sl("traversal", "traversal-exotic.txt",    "Directory Traversal/Intruder/traversals-8-deep-exotic-encoding.txt", "Exotic encoding traversal"),
        ],

        // ─── LDAP Injection ────────────────────────────────────────
        "ldap" => vec![
            sec("ldap", "ldap-fuzzing.txt",            "Fuzzing/LDAP.Fuzzing.txt",                     "LDAP fuzzing payloads"),
            sec("ldap", "ldap-ad-attributes.txt",      "Fuzzing/LDAP-active-directory-attributes.txt", "AD attributes"),
            sl("ldap", "ldap-patt-fuzz.txt",           "LDAP Injection/Intruder/LDAP_FUZZ.txt",        "PATT LDAP fuzz"),
            sl("ldap", "ldap-patt-small.txt",          "LDAP Injection/Intruder/LDAP_FUZZ_SMALL.txt",  "PATT LDAP small fuzz"),
            sl("ldap", "ldap-patt-attrs.txt",          "LDAP Injection/Intruder/LDAP_attributes.txt",  "LDAP attribute names"),
        ],

        // ─── NoSQL Injection ───────────────────────────────────────
        "nosql" => vec![
            sl("nosql", "nosql-mongodb.txt",           "NoSQL Injection/Intruder/MongoDB.txt",          "MongoDB injection"),
            sl("nosql", "nosql-generic.txt",           "NoSQL Injection/Intruder/NoSQL.txt",            "Generic NoSQL injection"),
        ],

        // ─── Open Redirect ─────────────────────────────────────────
        "open_redirect" => vec![
            sl("open_redirect", "redirect-wordlist.txt",   "Open Redirect/Intruder/open_redirect_wordlist.txt", "Open redirect wordlist"),
            sl("open_redirect", "redirect-payloads.txt",   "Open Redirect/Intruder/Open-Redirect-payloads.txt", "Redirect payloads"),
            sl("open_redirect", "redirect-openredirects.txt", "Open Redirect/Intruder/openredirects.txt",       "Open redirect variants"),
        ],

        // ─── Authentication ────────────────────────────────────────
        "auth" => vec![
            sec("auth", "common-passwords-top10k.txt", "Passwords/Common-Credentials/10k-most-common.txt", "Top 10k passwords"),
            sec("auth", "common-passwords-darkweb.txt","Passwords/Common-Credentials/darkweb2017_top-10000.txt", "Darkweb top 10000"),
            sec("auth", "common-passwords-top100.txt", "Passwords/Common-Credentials/darkweb2017_top-100.txt", "Darkweb top 100"),
            sec("auth", "common-passwords-top1000.txt","Passwords/Common-Credentials/darkweb2017_top-1000.txt", "Darkweb top 1000"),
        ],

        // ─── General Fuzzing ───────────────────────────────────────
        "fuzzing" => vec![
            sec("fuzzing", "special-chars.txt",        "Fuzzing/special-chars.txt",                     "Special characters"),
            sec("fuzzing", "unicode.txt",              "Fuzzing/Unicode.txt",                           "Unicode fuzzing"),
            sec("fuzzing", "big-naughty-strings.txt",  "Fuzzing/big-list-of-naughty-strings.txt",       "Big list of naughty strings"),
            sec("fuzzing", "metacharacters.txt",       "Fuzzing/Metacharacters.fuzzdb.txt",             "Metacharacters"),
            sec("fuzzing", "format-strings.txt",       "Fuzzing/FormatString-Jhaddix.txt",              "Format string payloads"),
            sec("fuzzing", "json-fuzzing.txt",         "Fuzzing/JSON.Fuzzing.txt",                      "JSON fuzzing"),
            sec("fuzzing", "fuzz-bo0om.txt",           "Fuzzing/fuzz-Bo0oM.txt",                        "Bo0oM fuzzing payloads"),
            sec("fuzzing", "html5sec.txt",             "Fuzzing/HTML5sec-Injections-Jhaddix.txt",        "HTML5 security injections"),
            sec("fuzzing", "uri-hex.txt",              "Fuzzing/URI-hex.txt",                            "URI hex encoding"),
            sec("fuzzing", "http-methods.txt",         "Fuzzing/http-request-methods.txt",               "HTTP request methods"),
            sec("fuzzing", "double-uri-hex.txt",       "Fuzzing/doble-uri-hex.txt",                      "Double URI hex encoding"),
            sec("fuzzing", "environment-ids.txt",      "Fuzzing/environment-identifiers.txt",            "Environment identifiers"),
            sl("fuzzing", "springboot-actuator.txt",    "Insecure Management Interface/Intruder/springboot_actuator.txt", "SpringBoot actuator"),
        ],

        _ => vec![],
    }
}

/// Helper: PayloadsAllTheThings source
fn sl(cat: &str, file: &str, path: &str, desc: &str) -> PayloadSource {
    PayloadSource {
        source_name: "payloadsallthethings".into(),
        category: cat.into(),
        filename: file.into(),
        url: format!("{}/{}", PT, path.replace(' ', "%20")),
        description: desc.into(),
    }
}

/// Helper: SecLists source
fn sec(cat: &str, file: &str, path: &str, desc: &str) -> PayloadSource {
    PayloadSource {
        source_name: "seclists".into(),
        category: cat.into(),
        filename: file.into(),
        url: format!("{}/{}", SL, path.replace(' ', "%20")),
        description: desc.into(),
    }
}
