//Welcome Notices
user_pref("browser.aboutwelcome.enabled", false);

//about:config warning
user_pref("browser.aboutConfig.showWarning", false);

//Disable Default Browser check
user_pref("browser.shell.checkDefaultBrowser", false);

//Startup - Home
user_pref("browser.startup.page", 1);

//Disable Firefox Home Content
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);

//Clear Default Topsites
user_pref("browser.newtabpage.activity-stream.default.sites", "");

//Disable Geolocation
user_pref("geo.provider.ms-windows-location", false);
user_pref("browser.region.update.enabled", false);
user_pref("browser.region.network.url", "");

//Disable Addons recommendation
user_pref("extensions.getAddons.showPane", false);
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);
user_pref("browser.discovery.enabled", false);

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

//New Tab Page telemetry
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);

//Experiments - Shield Studies
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");

//Crash Reports
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false);
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false);

//Detection of Wi-Fi Login pages and whether a user is online/offline
user_pref("captivedetect.canonicalURL", "");
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);

//Disable Safebrowsing
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.url", "");
user_pref("browser.safebrowsing.downloads.remote.block_potentially_unwanted", false);
user_pref("browser.safebrowsing.downloads.remote.block_uncommon", false);
user_pref("browser.safebrowsing.provider.google4.gethashURL", "");
user_pref("browser.safebrowsing.provider.google4.updateURL", "");
user_pref("browser.safebrowsing.provider.google.gethashURL", "");
user_pref("browser.safebrowsing.provider.google.updateURL", "");

//Disable Prefetching
user_pref("network.prefetch-next", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);
user_pref("network.predictor.enabled", false);
user_pref("network.predictor.enable-prefetch", false);
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("browser.places.speculativeConnect.enabled", false);

//Disable Disk Cache
user_pref("browser.cache.disk.enable", false);

//Tracking
user_pref("browser.contentblocking.category", "strict");

//Temp Downloads and Cleaning
user_pref("browser.download.start_downloads_in_tmp_dir", true);
user_pref("browser.helperApps.deleteTempFileOnExit", true);
user_pref("browser.download.forbid_open_with", true);

//URL Bar
user_pref("browser.urlbar.trimHttps", false);
user_pref("browser.urlbar.speculativeConnect.enabled", false);

//Disable Search Engine suggestions
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);
user_pref("browser.urlbar.trending.featureGate", false);
user_pref("browser.urlbar.quicksuggest.enabled", false);
user_pref("browser.urlbar.suggest.quicksuggest.nonsponsored", false);
user_pref("browser.urlbar.suggest.quicksuggest.sponsored", false);
user_pref("browser.urlbar.addons.featureGate", false);
user_pref("browser.urlbar.mdn.featureGate", false);
user_pref("browser.urlbar.yelp.featureGate", false);
user_pref("browser.urlbar.clipboard.featureGate", false);
user_pref("browser.urlbar.suggest.engines", false);
user_pref("browser.urlbar.fakespot.featureGate", false);
user_pref("browser.urlbar.pocket.featureGate", false);
user_pref("browser.urlbar.weather.featureGate", false);

//Disable Pocket
user_pref("extensions.pocket.enabled", false);
user_pref("extensions.pocket.api"," ");
user_pref("extensions.pocket.oAuthConsumerKey", " ");
user_pref("extensions.pocket.site", " ");
user_pref("extensions.pocket.showHome", false);

//Findbar to highlight all
user_pref("findbar.highlightAll", true);

//HTTPS only mode
user_pref("dom.security.https_only_mode", true);
user_pref("security.mixed_content.block_display_content", true);
user_pref("dom.security.https_only_mode_send_http_background_request", false);

//Remove permissions for Mozilla domains
user_pref("permissions.manager.defaultsUrl", "");

//Disable Autofill
user_pref("browser.formfill.enable", false);
user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("extensions.formautofill.creditCards.enabled", false);

//Disable Coloring of visited Links
user_pref("layout.css.visited_links_enabled", false);

//Disable Password and autofillinng
user_pref("signon.autofillForms", false);
user_pref("signon.formlessCapture.enabled", false);
user_pref("signon.rememberSignons", false);
user_pref("network.auth.subresource-http-auth-allow", 0);
user_pref("signon.generation.enabled", false);
user_pref("signon.management.page.breach-alerts.enabled", false);
user_pref("signon.management.page.breachAlertUrl", "");
user_pref("browser.contentblocking.report.lockwise.enabled", false);
user_pref("browser.contentblocking.report.lockwise.how_it_works.url", "");
user_pref("signon.firefoxRelay.feature", "");
user_pref("signon.storeWhenAutocompleteOff", false);

//Disable storing data, cookies
user_pref("browser.sessionstore.privacy_level", 2);

//Register with ARR Windows for session restart after crash or system restart
user_pref("toolkit.winRegisterApplicationRestart", false);
user_pref("browser.sessionstore.resume_from_crash", false);

//SSL
user_pref("security.ssl.require_safe_negotiation", true);
user_pref("security.tls.enable_0rtt_data", false);
user_pref("security.cert_pinning.enforcement_level", 2);

//Certificate Checks Crlite
user_pref("security.OCSP.enabled", 0);
user_pref("security.remote_settings.crlite_filters.enabled", true);
user_pref("security.pki.crlite_mode", 2);

//SSL and TLS Certificates and Handshakes
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);
user_pref("browser.xul.error_pages.expert_bad_cert", true);

//Send minimal info through header
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

//Prevet js from moving and resizing windows
user_pref("dom.disable_window_move_resize", true);

//Disable Firefox UI Tours of new features
user_pref("browser.uitour.enabled", false);

//Prevents Phishing attacks through converting the chars to ASCII
user_pref("network.IDN_show_punycode", true);

//Just a flag to show that privacy settings like history have been modified
user_pref("privacy.history.custom", true);

//Disable Web Compat
user_pref("privacy.antitracking.enableWebcompat", false);

//Disable Recommendations
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features", false);

//Hide "More from Mozilla"
user_pref("browser.preferences.moreFromMozilla", false);

//Extensions
user_pref("extensions.enabledScopes", 5);
user_pref("extensions.postDownloadThirdPartyPrompt", false);
user_pref("extensions.webextensions.restrictedDomains", "");
user_pref("extensions.quarantinedDomains.enabled", false);

//Events that can allow popup
user_pref("dom.popup_allowed_events", "click dblclick mousedown pointerdown");

//Mozilla VPN
user_pref("browser.privatebrowsing.vpnpromourl", "");

//Disable Firefox sync
user_pref("identity.fxaccounts.enabled", false);
user_pref("identity.fxaccounts.autoconfig.uri", "");

//Sends data when user leaves the pages
user_pref("beacon.enabled", false);

//Disable Hyperlink Auditing
user_pref("browser.send_pings", false);

//DNS
user_pref("network.trr.mode", 3);
user_pref("network.trr.uri", "https://security.cloudflare-dns.com/dns-query");
user_pref("network.trr.custom_uri", "https://security.cloudflare-dns.com/dns-query");
user_pref("doh-rollout.disable-heuristics", true);

//Dark Color Scheme
user_pref("layout.css.prefers-color-scheme.content-override", 0);

//Battery Status - open to Firefox browser and extensions
user_pref("dom.battery.enabled", false);

//Disable Remote Debugging - Default False
user_pref("devtools.debugger.remote-enabled", false);

//Accessibility
user_pref("accessibility.force_disabled", 1);
user_pref("devtools.accessibility.enabled", false);

//PPA
user_pref("dom.private-attribution.submission.enabled", false);
user_pref("toolkit.telemetry.dap_helper", "");
user_pref("toolkit.telemetry.dap_leader", "");

//PDF
user_pref("pdfjs.enableScripting", false);
user_pref("browser.download.open_pdf_attachments_inline", true);

//New Tab
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);
user_pref("browser.newtabpage.activity-stream.showWeather", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);

//Downloads
user_pref("browser.download.manager.addToRecentDocs", false);

//Cookies
user_pref("cookiebanners.service.mode", 1);

//Bookmarks
user_pref("browser.toolbars.bookmarks.visibility", "never");
user_pref("browser.tabs.loadBookmarksInTabs", true);
user_pref("browser.bookmarks.max_backups", 1);

//Leave Browser open even after closing the last tab
user_pref("browser.tabs.closeWindowWithLastTab", false);

//Not selecting the space next to a word while selecting a word
user_pref("layout.word_select.eat_space_to_next_word", false);
user_pref("editor.word_select.delete_space_after_doubleclick_selection", true);

//Disable ALT key
user_pref("ui.key.menuAccessKeyFocuses", false);

//Hide frequent sites while clicking on taskbar
user_pref("browser.taskbar.lists.enabled", false);
user_pref("browser.taskbar.lists.frequent.enabled", false);
user_pref("browser.taskbar.lists.recent.enabled", false);
user_pref("browser.taskbar.lists.tasks.enabled", false);

//URL Typos
user_pref("keyword.enabled", false);

//Other Telemetry
user_pref("network.trr.confirmation_telemetry_enabled", false);
user_pref("security.app_menu.recordEventTelemetry", false);
user_pref("browser.search.serpEventTelemetryCategorization.enabled", false);
user_pref("dom.security.unexpected_system_load_telemetry_enabled", false);
user_pref("privacy.trackingprotection.emailtracking.data_collection.enabled", false);
user_pref("messaging-system.rsexperimentloader.enabled", false);
user_pref("messaging-system.askForFeedback", false);
user_pref("signon.recipes.remoteRecipes.enabled", false);
user_pref("security.protectionspopup.recordEventTelemetry", false);
user_pref("security.certerrors.recordEventTelemetry", false);

//Theme
user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true);