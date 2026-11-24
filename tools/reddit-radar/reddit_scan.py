#!/usr/bin/env python3
"""Reddit roofing-demand collector — READ-ONLY. Operated by Zuck for Tommy Thomsen.

Auth: OAuth 2.0 authorization-code flow for an INSTALLED app (public client —
no client secret exists, so nothing secret ever changes hands). The account
owner authorizes in their own browser. The one-time code they hand back is
single-use and expires in ~10 minutes. The resulting refresh token is written
to ~/.config/reddit-radar/refresh_token (mode 0600) and never printed, never
stored in this repo, never sent to chat. Environment overrides:
    REDDIT_CLIENT_ID, REDDIT_REFRESH_TOKEN, REDDIT_USER_AGENT (optional)

Modes:
    --auth-url        Print the URL the account owner opens to authorize
                      (scopes: read identity, permanent). Owner copies the
                      `code` from the redirect address bar and hands it over.
    --exchange CODE   Trade that one-time code for a refresh token and store
                      it at ~/.config/reddit-radar/refresh_token (0600).
                      Prints only a confirmation — never the token.
    --scan            Pull new posts from configured subreddits, pre-filter by
                      signal phrases, dedupe against state, write a candidates
                      file for scoring. Uses ONLY read endpoints.

No write endpoint (comment/post/vote/DM) exists anywhere in this script.
Rate discipline: listing pulls are batched per subreddit; on HTTP 429 the run
stops and reports instead of retrying.
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import requests
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.yaml")
STATE_PATH = os.path.join(HERE, "scan-state.json")
TOKEN_URL = "https://www.reddit.com/api/v1/access_token"
AUTH_URL = "https://www.reddit.com/api/v1/authorize"
API = "https://oauth.reddit.com"


def load_config():
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def env(name, required=True):
    v = os.environ.get(name, "")
    if required and not v:
        print(f"BLOCKED: {name} is not set. Credentials come from the Secure "
              f"Vault at run time; nothing is stored in this repo.")
        sys.exit(2)
    return v


def user_agent():
    return env("REDDIT_USER_AGENT", required=False) or \
        "windows:roofing-demand-radar:v1.0 (read-only scanner)"


def auth_url(cfg):
    acct = cfg["accounts"][0]
    cid = env("REDDIT_CLIENT_ID")
    params = {
        "client_id": cid,
        "response_type": "code",
        "state": "radar-main",
        "redirect_uri": acct["redirect_uri"],
        "duration": "permanent",
        "scope": " ".join(acct["scopes"]),
    }
    q = "&".join(f"{k}={requests.utils.quote(str(v), safe='')}"
                 for k, v in params.items())
    print(f"{AUTH_URL}?{q}")
    print("\nOwner: open that URL while logged into the Reddit account being "
          "connected, approve, then copy the `code` value from the address "
          "bar of the page it redirects to (the page itself will not load — "
          "that is expected). Hand the code back promptly; it expires in "
          "~10 minutes and works once.")


TOKEN_FILE = os.path.expanduser("~/.config/reddit-radar/refresh_token")


def client_auth():
    # Installed app = public client: client_id as username, empty password.
    return (env("REDDIT_CLIENT_ID"), "")


def exchange(cfg, code):
    acct = cfg["accounts"][0]
    r = requests.post(
        TOKEN_URL,
        auth=client_auth(),
        data={"grant_type": "authorization_code", "code": code,
              "redirect_uri": acct["redirect_uri"]},
        headers={"User-Agent": user_agent()},
        timeout=30,
    )
    r.raise_for_status()
    tok = r.json()
    if "refresh_token" not in tok:
        print(f"No refresh token returned: {tok}")
        sys.exit(1)
    os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
    with open(TOKEN_FILE, "w") as f:
        f.write(tok["refresh_token"])
    os.chmod(TOKEN_FILE, 0o600)
    print(f"Connected. Refresh token stored at {TOKEN_FILE} (mode 0600). "
          f"Scopes granted: {tok.get('scope', 'read identity')}. "
          f"The token itself was not printed anywhere.")


def refresh_token():
    v = os.environ.get("REDDIT_REFRESH_TOKEN", "")
    if v:
        return v
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE) as f:
            return f.read().strip()
    print("BLOCKED: no refresh token found (env or token file). "
          "Run --auth-url and --exchange first.")
    sys.exit(2)


def access_token():
    r = requests.post(
        TOKEN_URL,
        auth=client_auth(),
        data={"grant_type": "refresh_token",
              "refresh_token": refresh_token()},
        headers={"User-Agent": user_agent()},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def load_state():
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH) as f:
            return json.load(f)
    return {"seen": {}, "last_run_utc": None}


def save_state(state):
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, indent=1)


def scan(cfg):
    token = access_token()
    headers = {"Authorization": f"bearer {token}",
               "User-Agent": user_agent()}
    cad = cfg["cadence"]
    now = datetime.now(timezone.utc)
    if cad.get("backfill_hours") and not load_state().get("last_run_utc"):
        cutoff = now - timedelta(hours=cad["backfill_hours"])
    else:
        cutoff = now - timedelta(hours=cad["scan_interval_hours"] + 1)
    max_age = now - timedelta(days=cad["max_post_age_days"])
    cutoff = max(cutoff, max_age)

    state = load_state()
    seen = state["seen"]
    # prune dedupe window
    horizon = (now - timedelta(days=cad["dedupe_window_days"])).timestamp()
    seen = {k: v for k, v in seen.items() if v > horizon}

    phrases = [p.lower() for p in cfg["signal_phrases"]]
    subs = cfg["core_subreddits"] + cfg["local_subreddits"]
    candidates = []
    pulled = 0
    for sub in subs:
        r = requests.get(f"{API}/r/{sub}/new",
                         headers=headers,
                         params={"limit": 100},
                         timeout=30)
        if r.status_code == 429:
            print(f"RATE LIMITED at r/{sub} — stopping run, no retries.")
            save_state({"seen": seen,
                        "last_run_utc": state.get("last_run_utc")})
            sys.exit(3)
        if r.status_code != 200:
            print(f"r/{sub}: HTTP {r.status_code} — skipped.")
            continue
        for child in r.json()["data"]["children"]:
            d = child["data"]
            pulled += 1
            created = datetime.fromtimestamp(d["created_utc"], timezone.utc)
            if created < cutoff or d["id"] in seen:
                continue
            text = (d.get("title", "") + " " + d.get("selftext", "")).lower()
            if not any(p in text for p in phrases):
                continue
            seen[d["id"]] = d["created_utc"]
            candidates.append({
                "id": d["id"],
                "title": d.get("title", ""),
                "subreddit": d.get("subreddit", sub),
                "url": "https://www.reddit.com" + d.get("permalink", ""),
                "created_utc": d["created_utc"],
                "author": d.get("author", ""),
                "excerpt": (d.get("selftext", "") or "")[:600],
                "num_comments": d.get("num_comments", 0),
            })
        time.sleep(1)  # courtesy pacing between subreddit pulls

    state = {"seen": seen, "last_run_utc": now.timestamp()}
    save_state(state)
    stamp = now.strftime("%Y%m%d-%H%M")
    out = os.path.join(HERE, f"candidates-{stamp}.json")
    with open(out, "w") as f:
        json.dump(candidates, f, indent=1)
    print(f"Pulled {pulled} posts from {len(subs)} subreddits since "
          f"{cutoff.isoformat()}. {len(candidates)} passed the signal "
          f"pre-filter -> {out}")
    print("Next step: Zuck scores candidates 1-10, surfaces 7+ only.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--auth-url", action="store_true")
    ap.add_argument("--exchange", metavar="CODE")
    ap.add_argument("--scan", action="store_true")
    args = ap.parse_args()
    cfg = load_config()
    if args.auth_url:
        auth_url(cfg)
    elif args.exchange:
        exchange(cfg, args.exchange)
    elif args.scan:
        scan(cfg)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
