#!/usr/bin/env python3
#   cloudflare-ddns.py
#   Summary: Access your home network remotely via a custom domain name without a static IP!
#   Description: Access your home network remotely via a custom domain
#                Access your home network remotely via a custom domain
#                A small, 🕵️ privacy centric, and ⚡
#                lightning fast multi-architecture Docker image for self hosting projects.

__version__ = "1.0.2"

from string import Template

import json
import os
import signal
import sys
import threading
import time
import requests
import logging
import ipaddress
from datetime import datetime

CONFIG_PATH = os.environ.get('CONFIG_PATH', os.getcwd())
# Read in all environment variables that have the correct prefix
ENV_VARS = {key: value for (key, value) in os.environ.items() if key.startswith('CF_DDNS_')}

log_level = os.environ.get('CF_DDNS_LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)

class GracefulExit:
    def __init__(self):
        self.kill_now = threading.Event()
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        print("🛑 Stopping main thread...")
        self.kill_now.set()

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def deleteEntries(type):
    # Helper function for deleting A or AAAA records
    # in the case of no IPv4 or IPv6 connection, yet
    # existing A or AAAA records are found.
    logger.debug(f"Starting deletion of {type} records")
    for option in config["cloudflare"]:
        logger.debug(f"Fetching {type} records for zone {option['zone_id']}")
        answer = cf_api(
            "zones/" + option['zone_id'] +
            "/dns_records?per_page=100&type=" + type,
            "GET", option)
        if answer is None or answer["result"] is None:
            logger.info(f"No {type} records found or error in fetching records")
            time.sleep(5)
            return
        for record in answer["result"]:
            identifier = str(record["id"])
            logger.debug(f"Deleting {type} record with ID {identifier}")
            response = cf_api(
                "zones/" + option['zone_id'] + "/dns_records/" + identifier,
                "DELETE", option)
            if response and response.get("success"):
                logger.info(f"Deleted stale record {identifier}")
            else:
                logger.error(f"Failed to delete stale record {identifier}")


def getIPs():
    a = None
    aaaa = None
    global ipv4_enabled
    global ipv6_enabled
    global purgeUnknownRecords
    if ipv4_enabled:
        try:
            logger.debug("Attempting to detect IPv4 via 1.1.1.1")
            a = requests.get(
                "https://1.1.1.1/cdn-cgi/trace").text.split("\n")
            a.pop()
            a = dict(s.split("=") for s in a)["ip"]
            logger.debug(f"Detected IPv4: {a}")
        except Exception:
            global shown_ipv4_warning
            if not shown_ipv4_warning:
                shown_ipv4_warning = True
                logger.warning("🧩 IPv4 not detected via 1.1.1.1, trying 1.0.0.1")
            # Try secondary IP check
            try:
                a = requests.get(
                    "https://1.0.0.1/cdn-cgi/trace").text.split("\n")
                a.pop()
                a = dict(s.split("=") for s in a)["ip"]
            except Exception:
                global shown_ipv4_warning_secondary
                if not shown_ipv4_warning_secondary:
                    shown_ipv4_warning_secondary = True
                    logger.error("🚫 IPv4 not detected via 1.0.0.1. Verify your ISP or DNS provider isn't blocking Cloudflare's IPs.")
                if purgeUnknownRecords:
                    logger.debug("Purging unknown A records since purgeUnknownRecords is enabled")
                    deleteEntries("A")
    if ipv6_enabled:
        try:
            logger.debug("Attempting to detect IPv6 via 1.1.1.1")
            aaaa = requests.get(
                "https://[2606:4700:4700::1111]/cdn-cgi/trace").text.split("\n")
            aaaa.pop()
            aaaa = dict(s.split("=") for s in aaaa)["ip"]
            logger.debug(f"Detected IPv6: {aaaa}")
        except Exception:
            global shown_ipv6_warning
            if not shown_ipv6_warning:
                shown_ipv6_warning = True
                logger.warning("🧩 IPv6 not detected via 1.1.1.1, trying 1.0.0.1")
            try:
                aaaa = requests.get(
                    "https://[2606:4700:4700::1001]/cdn-cgi/trace").text.split("\n")
                aaaa.pop()
                aaaa = dict(s.split("=") for s in aaaa)["ip"]
            except Exception:
                global shown_ipv6_warning_secondary
                if not shown_ipv6_warning_secondary:
                    shown_ipv6_warning_secondary = True
                    logger.error("🚫 IPv6 not detected via 1.0.0.1. Verify your ISP or DNS provider isn't blocking Cloudflare's IPs.")
                if purgeUnknownRecords:
                    logger.debug("Purging unknown AAAA records since purgeUnknownRecords is enabled")
                    deleteEntries("AAAA")
    ips = {}
    if (a is not None):
        if is_valid_ip(a):
            ips["ipv4"] = {
                "type": "A",
                "ip": a
            }
        else:
            logger.error(f"Invalid IPv4 address detected: {a}")
            return {}
    if (aaaa is not None):
        if is_valid_ip(aaaa):
            ips["ipv6"] = {
                "type": "AAAA",
                "ip": aaaa
            }
        else:
            logger.error(f"Invalid IPv6 address detected: {aaaa}")
            return {}
    return ips


def commitRecord(ip):
    global ttl
    for option in config["cloudflare"]:
        subdomains = option["subdomains"]
        response = cf_api("zones/" + option['zone_id'], "GET", option)
        if response is None or response["result"]["name"] is None:
            logger.warning("Failed to fetch zone information for zone_id: " + option['zone_id'] + ". Retrying in 5 seconds.")
            time.sleep(5)
            return
        base_domain_name = response["result"]["name"]
        for subdomain in subdomains:
            try:
                name = subdomain["name"].lower().strip()
                proxied = subdomain["proxied"]
                logger.debug(f"Processing subdomain: {name}, proxied: {proxied}")
            except:
                name = subdomain
                proxied = option["proxied"]
            fqdn = base_domain_name
            if name != '' and name != '@':
                fqdn = name + "." + base_domain_name
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            record = {
                "type": ip["type"],
                "name": fqdn,
                "content": ip["ip"],
                "proxied": proxied,
                "ttl": ttl,
                "comment": f"Updated by Cloudflare DDNS at {timestamp}."
            }
            dns_records = cf_api(
                "zones/" + option['zone_id'] +
                "/dns_records?per_page=100&type=" + ip["type"],
                "GET", option)
            identifier = None
            modified = False
            duplicate_ids = []
            if dns_records is not None:
                for r in dns_records["result"]:
                    logger.debug(f"Checking DNS record: {r}")
                    if (r["name"] == fqdn):
                        if identifier:
                            if r["content"] == ip["ip"]:
                                logger.debug(f"Duplicate record found with ID {identifier} and content {r['content']}")
                                duplicate_ids.append(identifier)
                                identifier = r["id"]
                            else:
                                logger.debug(f"Stale record found with ID {r['id']} and content {r['content']}")
                                duplicate_ids.append(r["id"])
                        else:
                            identifier = r["id"]
                            if r['content'] != record['content'] or r['proxied'] != record['proxied']:
                                modified = True
                                logger.debug(f"Record {identifier} has been modified. Current content: {r['content']}, new content: {record['content']}. Current proxied: {r['proxied']}, new proxied: {record['proxied']}")
            if identifier:
                if modified:
                    logger.info("📡 Updating record " + str(record))
                    response = cf_api(
                        "zones/" + option['zone_id'] +
                        "/dns_records/" + identifier,
                        "PUT", option, {}, record)
                else:
                    logger.info("No changes detected for record " + str(record))
            else:
                logger.info("➕ Adding new record " + str(record))
                response = cf_api(
                    "zones/" + option['zone_id'] + "/dns_records", "POST", option, {}, record)
            if purgeUnknownRecords:
                for identifier in duplicate_ids:
                    identifier = str(identifier)
                    logger.info("🗑️ Deleting stale record " + identifier)
                    response = cf_api(
                        "zones/" + option['zone_id'] +
                        "/dns_records/" + identifier,
                        "DELETE", option)
    return True


def updateLoadBalancer(ip):

    for option in config["load_balancer"]:
        pools = cf_api('user/load_balancers/pools', 'GET', option)

        if pools:
            idxr = dict((p['id'], i) for i, p in enumerate(pools['result']))
            idx = idxr.get(option['pool_id'])

            origins = pools['result'][idx]['origins']

            idxr = dict((o['name'], i) for i, o in enumerate(origins))
            idx = idxr.get(option['origin'])

            origins[idx]['address'] = ip['ip']
            data = {'origins': origins}

            response = cf_api(f'user/load_balancers/pools/{option["pool_id"]}', 'PATCH', option, {}, data)


def cf_api(endpoint, method, config, headers={}, data=False):
    api_token = config['authentication']['api_token']
    if api_token != '' and api_token != 'api_token_here':
        headers = {
            "Authorization": "Bearer " + api_token, **headers
        }
    else:
        headers = {
            "X-Auth-Email": config['authentication']['api_key']['account_email'],
            "X-Auth-Key": config['authentication']['api_key']['api_key'],
        }
    try:
        if (data == False):
            response = requests.request(
                method, "https://api.cloudflare.com/client/v4/" + endpoint, headers=headers)
        else:
            response = requests.request(
                method, "https://api.cloudflare.com/client/v4/" + endpoint,
                headers=headers, json=data)

        if response.ok:
            return response.json()
        else:
            print("😡 Error sending '" + method +
                  "' request to '" + response.url + "':")
            print(response.text)
            return None
    except Exception as e:
        print("😡 An exception occurred while sending '" +
              method + "' request to '" + endpoint + "': " + str(e))
        return None


def updateIPs(ips):
    for ip in ips.values():
        commitRecord(ip)
        #updateLoadBalancer(ip)


if __name__ == '__main__':
    shown_ipv4_warning = False
    shown_ipv4_warning_secondary = False
    shown_ipv6_warning = False
    shown_ipv6_warning_secondary = False
    ipv4_enabled = True
    ipv6_enabled = True
    purgeUnknownRecords = False

    if sys.version_info < (3, 5):
        raise Exception("🐍 This script requires Python 3.5+")

    config = None
    try:
        config_file_path = os.path.join(CONFIG_PATH, "config.json")
        logger.debug(f"Attempting to open config file at: {config_file_path}")
        with open(config_file_path) as config_file:
            if len(ENV_VARS) != 0:
                logger.debug(f"Substituting environment variables into the configuration. Environment variables found: {', '.join(ENV_VARS.keys())}")
                config = json.loads(Template(config_file.read()).safe_substitute(ENV_VARS))
            else:
                logger.debug("No environment variables found, reading config as is.")
                config = json.loads(config_file.read())
    except:
        logger.error("😡 Error reading config.json", exc_info=True)
        # wait 10 seconds to prevent excessive logging on docker auto restart
        time.sleep(10)

    if config is not None:
        try:
            ipv4_enabled = config["a"]
            ipv6_enabled = config["aaaa"]
        except:
            ipv4_enabled = True
            ipv6_enabled = True
            print("⚙️ Individually disable IPv4 or IPv6 with new config.json options. Read more about it here: https://github.com/timothymiller/cloudflare-ddns/blob/master/README.md")
        try:
            purgeUnknownRecords = config["purgeUnknownRecords"]
        except:
            purgeUnknownRecords = False
            print("⚙️ No config detected for 'purgeUnknownRecords' - defaulting to False")
        try:
            ttl = int(config["ttl"])
        except:
            ttl = 300  # default Cloudflare TTL
            print(
                "⚙️ No config detected for 'ttl' - defaulting to 300 seconds (5 minutes)")
        if ttl < 30:
            ttl = 1  #
            print("⚙️ TTL is too low - defaulting to 1 (auto)")
        if (len(sys.argv) > 1):
            if (sys.argv[1] == "--repeat"):
                if ipv4_enabled and ipv6_enabled:
                    print(
                        "🕰️ Updating IPv4 (A) & IPv6 (AAAA) records every " + str(ttl) + " seconds")
                elif ipv4_enabled and not ipv6_enabled:
                    print("🕰️ Updating IPv4 (A) records every " +
                          str(ttl) + " seconds")
                elif ipv6_enabled and not ipv4_enabled:
                    print("🕰️ Updating IPv6 (AAAA) records every " +
                          str(ttl) + " seconds")
                next_time = time.time()
                killer = GracefulExit()
                prev_ips = None
                while True:
                    updateIPs(getIPs())
                    if killer.kill_now.wait(ttl):
                        break
            else:
                print("❓ Unrecognized parameter '" +
                      sys.argv[1] + "'. Stopping now.")
        else:
            updateIPs(getIPs())
