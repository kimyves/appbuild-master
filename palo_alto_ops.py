#!/usr/bin/env python3
"""Utility helpers for common Palo Alto PAN-OS operations.

Features:
- Create a security/firewall rule
- Configure URL egress whitelist entries through a custom URL category
"""

from __future__ import annotations

import argparse
import ssl
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Iterable, List, Optional


class PaloAltoAPIError(RuntimeError):
    """Raised when PAN-OS API returns an error response."""


@dataclass
class PaloAltoClient:
    host: str
    username: str
    password: str
    verify_ssl: bool = True
    vsys: str = "vsys1"

    def __post_init__(self) -> None:
        self.base_url = f"https://{self.host}/api/"
        self._api_key: Optional[str] = None
        self._ssl_context: Optional[ssl.SSLContext] = None
        if not self.verify_ssl:
            self._ssl_context = ssl._create_unverified_context()

    def _open(self, params: dict[str, str]) -> str:
        query = urllib.parse.urlencode(params)
        url = f"{self.base_url}?{query}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, context=self._ssl_context) as resp:
            return resp.read().decode("utf-8")

    def api_key(self) -> str:
        if self._api_key:
            return self._api_key
        response = self._open(
            {
                "type": "keygen",
                "user": self.username,
                "password": self.password,
            }
        )
        key = _extract_xml_value(response, "key")
        if not key:
            raise PaloAltoAPIError(f"Unable to retrieve API key: {response}")
        self._api_key = key
        return key

    def _request(self, params: dict[str, str]) -> str:
        full_params = {"key": self.api_key(), **params}
        response = self._open(full_params)
        if "status=\"error\"" in response:
            raise PaloAltoAPIError(response)
        return response

    def set_config(self, xpath: str, element_xml: str) -> str:
        return self._request(
            {
                "type": "config",
                "action": "set",
                "xpath": xpath,
                "element": element_xml,
            }
        )

    def edit_config(self, xpath: str, element_xml: str) -> str:
        return self._request(
            {
                "type": "config",
                "action": "edit",
                "xpath": xpath,
                "element": element_xml,
            }
        )

    def commit(self, description: Optional[str] = None) -> str:
        if description:
            cmd = f"<commit><description>{_xml_escape(description)}</description></commit>"
        else:
            cmd = "<commit></commit>"
        return self._request({"type": "commit", "cmd": cmd})

    def create_security_rule(
        self,
        rule_name: str,
        source_zones: Iterable[str],
        destination_zones: Iterable[str],
        source_addresses: Iterable[str],
        destination_addresses: Iterable[str],
        applications: Iterable[str],
        services: Iterable[str],
        action: str = "allow",
        description: str = "",
    ) -> str:
        rule_xpath = (
            f"/config/devices/entry/vsys/entry[@name='{self.vsys}']/rulebase/security/rules/entry[@name='{rule_name}']"
        )
        xml = (
            f"<from>{_members_xml(source_zones)}</from>"
            f"<to>{_members_xml(destination_zones)}</to>"
            f"<source>{_members_xml(source_addresses)}</source>"
            f"<destination>{_members_xml(destination_addresses)}</destination>"
            f"<application>{_members_xml(applications)}</application>"
            f"<service>{_members_xml(services)}</service>"
            f"<action>{_xml_escape(action)}</action>"
        )
        if description:
            xml += f"<description>{_xml_escape(description)}</description>"
        return self.edit_config(rule_xpath, f"<entry name='{_xml_escape(rule_name)}'>{xml}</entry>")

    def configure_url_egress_whitelist(
        self,
        category_name: str,
        urls: Iterable[str],
        profile_name: str,
    ) -> List[str]:
        cat_xpath = (
            f"/config/devices/entry/vsys/entry[@name='{self.vsys}']/profiles/custom-url-category"
        )
        cat_xml = (
            f"<entry name='{_xml_escape(category_name)}'>"
            "<type>URL List</type>"
            f"<list>{_members_xml(urls)}</list>"
            "</entry>"
        )
        category_result = self.set_config(cat_xpath, cat_xml)

        profile_xpath = (
            f"/config/devices/entry/vsys/entry[@name='{self.vsys}']/profiles/url-filtering/entry[@name='{profile_name}']/rules"
        )
        profile_xml = (
            f"<entry name='{_xml_escape(category_name)}'>"
            f"<action>allow</action><category><member>{_xml_escape(category_name)}</member></category>"
            "</entry>"
        )
        profile_result = self.set_config(profile_xpath, profile_xml)
        return [category_result, profile_result]


def _members_xml(items: Iterable[str]) -> str:
    members = "".join(f"<member>{_xml_escape(i)}</member>" for i in items)
    if not members:
        members = "<member>any</member>"
    return members


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _extract_xml_value(xml_text: str, tag: str) -> Optional[str]:
    open_tag = f"<{tag}>"
    close_tag = f"</{tag}>"
    start = xml_text.find(open_tag)
    end = xml_text.find(close_tag)
    if start == -1 or end == -1 or end <= start:
        return None
    return xml_text[start + len(open_tag) : end]


def _split_csv(value: str) -> List[str]:
    return [x.strip() for x in value.split(",") if x.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Palo Alto automation operations")
    parser.add_argument("--host", required=True, help="Firewall hostname or IP")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--vsys", default="vsys1")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    parser.add_argument("--commit", action="store_true", help="Commit after applying change")

    sub = parser.add_subparsers(dest="operation", required=True)

    rule = sub.add_parser("create-rule", help="Create/update a security rule")
    rule.add_argument("--name", required=True)
    rule.add_argument("--from-zones", required=True, help="Comma-separated source zones")
    rule.add_argument("--to-zones", required=True, help="Comma-separated destination zones")
    rule.add_argument("--source-addresses", default="any")
    rule.add_argument("--destination-addresses", default="any")
    rule.add_argument("--applications", default="any")
    rule.add_argument("--services", default="application-default")
    rule.add_argument("--action", default="allow", choices=["allow", "deny", "drop", "reset-client", "reset-server", "reset-both"])
    rule.add_argument("--description", default="")

    whitelist = sub.add_parser("url-whitelist", help="Configure URL egress whitelist")
    whitelist.add_argument("--category-name", required=True, help="Custom URL category name")
    whitelist.add_argument("--profile-name", required=True, help="URL filtering profile")
    whitelist.add_argument("--urls", required=True, help="Comma-separated URL patterns")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    client = PaloAltoClient(
        host=args.host,
        username=args.username,
        password=args.password,
        verify_ssl=not args.insecure,
        vsys=args.vsys,
    )

    try:
        if args.operation == "create-rule":
            output = client.create_security_rule(
                rule_name=args.name,
                source_zones=_split_csv(args.from_zones),
                destination_zones=_split_csv(args.to_zones),
                source_addresses=_split_csv(args.source_addresses),
                destination_addresses=_split_csv(args.destination_addresses),
                applications=_split_csv(args.applications),
                services=_split_csv(args.services),
                action=args.action,
                description=args.description,
            )
            print(output)
        elif args.operation == "url-whitelist":
            for result in client.configure_url_egress_whitelist(
                category_name=args.category_name,
                urls=_split_csv(args.urls),
                profile_name=args.profile_name,
            ):
                print(result)

        if args.commit:
            print(client.commit(description=f"Automated change: {args.operation}"))

    except PaloAltoAPIError as err:
        print(f"PAN-OS API error: {err}", file=sys.stderr)
        return 2
    except Exception as err:  # safety net for CLI usage
        print(f"Unexpected error: {err}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
