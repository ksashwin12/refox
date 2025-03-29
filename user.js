//Disable Disk Cache
user_pref("browser.cache.disk.enable", false);

//Tracking
user_pref("browser.contentblocking.category", "strict");

//Global Privacy Control
user_pref("privacy.globalprivacycontrol.enabled", true);

//Temp Downloads and Cleaning
user_pref("browser.download.start_downloads_in_tmp_dir", true);
user_pref("browser.helperApps.deleteTempFileOnExit", true);

//Certificate Checks Crlite
user_pref("security.remote_settings.crlite_filters.enabled", true);
user_pref("security.pki.crlite_mode", 2);

//SSL and TLS Certificates and Handshakes
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);
user_pref("browser.xul.error_pages.expert_bad_cert", true);
user_pref("security.tls.enable_0rtt_data", false);

//Just a flag to show that privacy settings like history have been modified
user_pref("privacy.history.custom", true);

//Show Https
user_pref("browser.urlbar.trimHttps", false);

//Disable Autofill
user_pref("browser.formfill.enable", false);

//Disable Search Engine suggestions
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.quicksuggest.enabled", false);

//Prevents Phishing attacks through converting the chars to ASCII
user_pref("network.IDN_show_punycode", true);

//Disable Password and autofillinng
user_pref("signon.autofillForms", false);
user_pref("signon.formlessCapture.enabled", false);
user_pref("signon.rememberSignons", false);

//Send minimal info through header
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

//HTTPS only mode
user_pref("dom.security.https_only_mode", true);

//Disbale Pocket
user_pref("extensions.pocket.enabled", false);

//Findbar to highlight all
user_pref("findbar.highlightAll", true);

//Crash Reports
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false);

//Experiments - Shield Studies
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");

//Detection of Wi-Fi Login pages and whether a user is online/offline
user_pref("captivedetect.canonicalURL", "");
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);

//Telemetry Core
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.server", "data:,");
user_pref("toolkit.telemetry.archive.enabled", false);

//Telemetry Pings during specific process
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);

//Checks how many users opt into telemetry
user_pref("toolkit.telemetry.coverage.opt-out", true);
user_pref("toolkit.coverage.opt-out", true);
user_pref("toolkit.coverage.endpoint.base", "");

//New tab page Telemetry
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);
