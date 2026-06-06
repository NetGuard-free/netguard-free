MALICIOUS_DOMAINS = {
    "phishing-test.com", "malware-c2.net", "eviltracker.xyz",
    "tracking.evil.ru",
}

COMPANION_DOMAINS: dict[str, list[str]] = {
    "youtube.com":   ["ytimg.com", "googlevideo.com", "youtu.be", "yt3.ggpht.com", "youtubei.googleapis.com"],
    "tiktok.com":    ["tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com", "bytedance.com", "musical.ly"],
    "instagram.com": ["cdninstagram.com", "fbcdn.net"],
    "facebook.com":  ["fbcdn.net", "fb.com", "fbsbx.com"],
    "twitter.com":   ["twimg.com", "t.co"],
    "reddit.com":    ["redd.it", "redditmedia.com", "redditstatic.com", "reddit.map.fastly.net"],
    "snapchat.com":  ["sc-cdn.net", "snap.com"],
    "twitch.tv":     ["twitchsvc.net", "jtvnw.net", "twitchassets.com"],
    "roblox.com":    ["rbxcdn.com", "rbxtrk.com"],
}

CHILD_BLOCK_DOMAINS = {
    "pornhub.com", "xvideos.com", "xhamster.com", "xnxx.com", "redtube.com",
    "youporn.com", "tube8.com", "beeg.com", "livejasmin.com", "chaturbate.com",
    "onlyfans.com", "brazzers.com", "bangbros.com", "naughtyamerica.com",
    "realitykings.com", "mofos.com", "twistys.com", "vivid.com",
    "playboyplus.com", "hustler.com", "penthouse.com", "sex.com",
    "xhamsterlive.com", "stripchat.com", "cam4.com", "myfreecams.com",
    "erowid.org", "bluelight.org", "shroomery.org", "rollsafe.org",
    "silkroad.com", "drugsforum.com",
    "bestgore.com", "liveleak.com",
}

DNS_WHITELIST_SUFFIXES = {
    "ip6.arpa",
    "in-addr.arpa",
    "local",
    "localhost",
}

CHILD_SAFESEARCH_DOMAINS = {
    "google.com":         "216.239.38.120",
    "www.google.com":     "216.239.38.120",
    "google.pl":          "216.239.38.120",
    "www.google.pl":      "216.239.38.120",
    "bing.com":           "204.79.197.220",
    "www.bing.com":       "204.79.197.220",
    "youtube.com":        "216.239.38.119",
    "www.youtube.com":    "216.239.38.119",
    "duckduckgo.com":     "52.149.246.39",
    "www.duckduckgo.com": "52.149.246.39",
}

TOR_EXIT_NODES = {
    "185.220.101.0", "185.220.102.0", "45.154.255.0",
}

COMMON_PORTS = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP",
    25: "SMTP", 587: "SMTP", 993: "IMAP", 3389: "RDP", 8080: "HTTP-alt",
    8767: "NetGuard", 5353: "mDNS", 67: "DHCP", 123: "NTP",
    1900: "UPnP", 5050: "Webhook",
}

FREE_LIMITS = {"max_devices": 5, "history_days": 7}
HOME_LIMITS = {"max_devices": 25, "history_days": 30}
ENTERPRISE_LIMITS = {"max_devices": None, "history_days": 365}


def _expand_blocked(blocked_list: list) -> set:
    result = set(blocked_list)
    for b in blocked_list:
        for companion in COMPANION_DOMAINS.get(b, []):
            result.add(companion)
    return result
