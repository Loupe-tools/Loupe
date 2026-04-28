#!/usr/bin/env python3
"""Generate large CSV files that mimic parsed Microsoft 365 / Okta unified audit logs.

Usage
-----
    python scripts/generate_sample_csv.py                        # 1 M rows → sample_logs.csv
    python scripts/generate_sample_csv.py --rows 500000 -o big.csv
    python scripts/generate_sample_csv.py --seed 42              # reproducible output

Zero external dependencies — stdlib only.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from io import StringIO

# ---------------------------------------------------------------------------
# Data pools
# ---------------------------------------------------------------------------

FIRST_NAMES = [
    "james", "mary", "robert", "patricia", "john", "jennifer", "michael",
    "linda", "david", "elizabeth", "william", "barbara", "richard", "susan",
    "joseph", "jessica", "thomas", "sarah", "charles", "karen", "daniel",
    "lisa", "matthew", "nancy", "anthony", "betty", "mark", "margaret",
    "donald", "sandra", "steven", "ashley", "paul", "kimberly", "andrew",
    "emily", "joshua", "donna", "kenneth", "michelle", "kevin", "carol",
    "brian", "amanda", "george", "dorothy", "timothy", "melissa", "ronald",
    "deborah",
]

LAST_NAMES = [
    "smith", "johnson", "williams", "brown", "jones", "garcia", "miller",
    "davis", "rodriguez", "martinez", "hernandez", "lopez", "gonzalez",
    "wilson", "anderson", "thomas", "taylor", "moore", "jackson", "martin",
    "lee", "perez", "thompson", "white", "harris", "sanchez", "clark",
    "ramirez", "lewis", "robinson",
]

DOMAINS = [
    "contoso.com", "fabrikam.com", "woodgrovebank.com", "adatum.com",
    "northwindtraders.com", "litwareinc.com",
]

# Weighted event definitions: (event_name, workload, weight)
# Higher weight = more frequent
EVENTS = [
    # --- Microsoft 365 / Entra ID (Azure AD) ---
    ("UserLoggedIn",                "AzureActiveDirectory", 300),
    ("UserLoginFailed",             "AzureActiveDirectory", 60),
    ("PasswordLogonInitialAuthUsingPassword", "AzureActiveDirectory", 40),
    ("ForeignRealmIndexLogonInitialAuthUsingADFSFederatedToken", "AzureActiveDirectory", 15),
    ("Add member to role.",         "AzureActiveDirectory", 8),
    ("Remove member from role.",    "AzureActiveDirectory", 5),
    ("Update user.",                "AzureActiveDirectory", 12),
    ("Disable account.",            "AzureActiveDirectory", 3),
    ("Reset user password.",        "AzureActiveDirectory", 6),
    ("Add app role assignment grant to user.", "AzureActiveDirectory", 5),
    ("Consent to application.",     "AzureActiveDirectory", 4),
    ("Update application.",         "AzureActiveDirectory", 3),
    ("Add service principal.",      "AzureActiveDirectory", 2),
    ("Set domain authentication.",  "AzureActiveDirectory", 1),
    # --- Exchange Online ---
    ("MailItemsAccessed",           "Exchange", 120),
    ("Send",                        "Exchange", 80),
    ("MoveToDeletedItems",          "Exchange", 30),
    ("Create",                      "Exchange", 25),
    ("Update",                      "Exchange", 20),
    ("HardDelete",                  "Exchange", 8),
    ("Set-Mailbox",                 "Exchange", 4),
    ("New-InboxRule",               "Exchange", 6),
    ("Set-InboxRule",               "Exchange", 3),
    ("Remove-InboxRule",            "Exchange", 2),
    ("UpdateInboxRules",            "Exchange", 5),
    ("MailboxLogin",                "Exchange", 40),
    ("SearchQueryInitiatedExchange","Exchange", 15),
    # --- SharePoint / OneDrive ---
    ("FileAccessed",                "SharePoint", 100),
    ("FileDownloaded",              "SharePoint", 50),
    ("FileUploaded",                "SharePoint", 35),
    ("FileModified",                "SharePoint", 40),
    ("FileDeleted",                 "SharePoint", 10),
    ("FileMoved",                   "SharePoint", 8),
    ("FileRenamed",                 "SharePoint", 6),
    ("FileCopied",                  "SharePoint", 5),
    ("FolderCreated",               "SharePoint", 7),
    ("FolderDeleted",               "SharePoint", 3),
    ("SharingSet",                  "SharePoint", 12),
    ("AnonymousLinkCreated",        "SharePoint", 4),
    ("CompanyLinkCreated",          "SharePoint", 6),
    ("SharingInvitationCreated",    "SharePoint", 5),
    ("SearchQueryInitiatedSharePoint","SharePoint", 10),
    ("SiteCollectionAdminAdded",    "SharePoint", 2),
    # --- OneDrive-specific ---
    ("FileSyncDownloadedFull",      "OneDrive", 30),
    ("FileSyncUploadedFull",        "OneDrive", 25),
    ("FileAccessedExtended",        "OneDrive", 15),
    # --- Okta ---
    ("user.session.start",          "Okta", 100),
    ("user.session.end",            "Okta", 50),
    ("user.authentication.sso",     "Okta", 80),
    ("user.authentication.auth_via_mfa",  "Okta", 60),
    ("user.authentication.verify",  "Okta", 25),
    ("user.account.lock",           "Okta", 5),
    ("user.account.unlock",         "Okta", 3),
    ("user.mfa.factor.activate",    "Okta", 8),
    ("user.mfa.factor.deactivate",  "Okta", 3),
    ("user.lifecycle.create",       "Okta", 4),
    ("user.lifecycle.deactivate",   "Okta", 2),
    ("user.lifecycle.suspend",      "Okta", 1),
    ("user.lifecycle.activate",     "Okta", 3),
    ("policy.evaluate_sign_on",     "Okta", 70),
    ("policy.rule.evaluate",        "Okta", 40),
    ("app.user_membership.add",     "Okta", 6),
    ("app.user_membership.remove",  "Okta", 4),
    ("group.user_membership.add",   "Okta", 5),
    ("group.user_membership.remove","Okta", 3),
    ("system.api_token.create",     "Okta", 1),
    ("application.lifecycle.create","Okta", 1),
    ("zone.update",                 "Okta", 1),
    # --- Microsoft Defender / Security ---
    ("AlertTriggered",              "SecurityComplianceCenter", 3),
    ("AlertResolved",               "SecurityComplianceCenter", 2),
    ("TIMailData-EmailEvents",      "ThreatIntelligence", 5),
]

EVENT_NAMES   = [e[0] for e in EVENTS]
EVENT_LOADS   = [e[1] for e in EVENTS]
EVENT_WEIGHTS = [e[2] for e in EVENTS]

# Map certain events to forced outcomes
FAILURE_EVENTS = {
    "UserLoginFailed", "user.account.lock",
}
SUCCESS_BIAS_EVENTS = {
    "UserLoggedIn", "MailItemsAccessed", "FileAccessed", "FileDownloaded",
    "user.session.start", "user.authentication.sso",
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0; Pro)",
    "Microsoft Office/16.0 (Macintosh; Mac OS X 14.5; Microsoft Outlook 16.0)",
    "MSAL/1.0 (iOS; 17.5; iPhone14,2)",
    "okta-auth-js/7.5.1 okta-signin-widget-7.14.0",
    "Mozilla/5.0 (compatible; MSAL 1.0)",
    "python-requests/2.31.0",
    "axios/1.6.8",
    "PostmanRuntime/7.37.3",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/24124.0.0.0 Chrome/120.0.0.0 Electron/28.0.0 Safari/537.36",
    "Dalvik/2.1.0 (Linux; U; Android 14; SM-S918B Build/UP1A.231005.007)",
    "Azure AD Graph API/1.0",
    "Microsoft Graph Client SDK 5.56.0",
]

CITIES = [
    ("New York",   "US", 40.7128, -74.0060),
    ("London",     "GB", 51.5074, -0.1278),
    ("San Francisco","US", 37.7749, -122.4194),
    ("Berlin",     "DE", 52.5200, 13.4050),
    ("Tokyo",      "JP", 35.6762, 139.6503),
    ("Sydney",     "AU", -33.8688, 151.2093),
    ("Toronto",    "CA", 43.6532, -79.3832),
    ("Paris",      "FR", 48.8566, 2.3522),
    ("Mumbai",     "IN", 19.0760, 72.8777),
    ("São Paulo",  "BR", -23.5505, -46.6333),
    ("Singapore",  "SG", 1.3521, 103.8198),
    ("Amsterdam",  "NL", 52.3676, 4.9041),
    ("Seoul",      "KR", 37.5665, 126.9780),
    ("Dubai",      "AE", 25.2048, 55.2708),
    ("Chicago",    "US", 41.8781, -87.6298),
    ("Stockholm",  "SE", 59.3293, 18.0686),
]

TARGET_APPS = [
    "Office 365 Exchange Online", "Office 365 SharePoint Online",
    "Microsoft Teams", "Microsoft Graph", "Azure Portal",
    "Salesforce.com", "ServiceNow", "Slack", "Zoom", "AWS Console",
    "Okta Dashboard", "Workday", "Box", "Dropbox Business",
    "Google Workspace", "Jira Cloud", "Confluence Cloud",
]

SHAREPOINT_SITES = [
    "https://contoso.sharepoint.com/sites/Engineering",
    "https://contoso.sharepoint.com/sites/Marketing",
    "https://contoso.sharepoint.com/sites/Legal",
    "https://contoso.sharepoint.com/sites/HR",
    "https://contoso.sharepoint.com/sites/Finance",
    "https://contoso.sharepoint.com/sites/Executive",
    "https://contoso.sharepoint.com/personal/jsmith_contoso_com",
    "https://contoso.sharepoint.com/personal/mjones_contoso_com",
]

FILE_NAMES = [
    "Q4_Financial_Report.xlsx", "Board_Presentation.pptx",
    "Employee_Directory.csv", "Project_Plan_2025.docx",
    "Architecture_Diagram.vsdx", "Meeting_Notes.docx",
    "Budget_Template.xlsx", "Sales_Pipeline.xlsx",
    "Legal_Agreement_Draft.pdf", "Onboarding_Guide.pdf",
    "API_Documentation.md", "Security_Audit_Report.pdf",
    "invoice_2025_001.pdf", "contract_renewal.docx",
    "marketing_campaign.pptx", "customer_data_export.csv",
    "source_code_review.zip", "deployment_runbook.docx",
]

INBOX_RULE_NAMES = [
    "Move to Archive", "Forward to Personal", "Delete Spam",
    "Move Newsletters", "Auto-reply OOO", "Flag Important",
    "Move from Boss", "Delete Notifications",
]

OS_LIST = [
    "Windows 10", "Windows 11", "macOS 14.5", "macOS 15.0",
    "iOS 17.5", "Android 14", "Linux", "ChromeOS",
]

BROWSER_LIST = [
    "Chrome 125", "Edge 124", "Firefox 126", "Safari 17.4",
    "Safari Mobile 17.5", "Chrome Mobile 125", "Electron 28",
]

AUTH_METHODS = [
    "Password", "FIDO2", "Microsoft Authenticator",
    "SMS OTP", "Email OTP", "Push Notification",
    "Hardware Token", "Certificate", "Windows Hello",
]

MFA_FACTORS = [
    "okta_verify:push", "okta_verify:totp", "google_authenticator",
    "sms", "email", "webauthn", "duo_security", "yubikey_token:hardware",
]

RECORD_TYPES = {
    "AzureActiveDirectory": 15,
    "Exchange": 2,
    "SharePoint": 6,
    "OneDrive": 6,
    "Okta": 99,
    "SecurityComplianceCenter": 40,
    "ThreatIntelligence": 28,
}

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def build_user_pool(rng: random.Random, count: int = 50) -> list[dict]:
    """Pre-generate a pool of user identities."""
    users = []
    used = set()
    while len(users) < count:
        first = rng.choice(FIRST_NAMES)
        last = rng.choice(LAST_NAMES)
        domain = rng.choice(DOMAINS)
        email = f"{first}.{last}@{domain}"
        if email in used:
            continue
        used.add(email)
        display = f"{first.title()} {last.title()}"
        uid = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        users.append({
            "email": email,
            "display": display,
            "id": uid,
            "domain": domain,
            "upn": email,
        })
    return users


def random_external_ip(rng: random.Random) -> str:
    """Generate a plausible external IPv4 address (avoids private ranges)."""
    while True:
        a = rng.randint(1, 223)
        if a in (10, 127):
            continue
        b = rng.randint(0, 255)
        if a == 172 and 16 <= b <= 31:
            continue
        if a == 192 and b == 168:
            continue
        return f"{a}.{b}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def random_internal_ip(rng: random.Random) -> str:
    return f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def pick_ip(rng: random.Random) -> str:
    return random_internal_ip(rng) if rng.random() < 0.15 else random_external_ip(rng)


def pick_outcome(rng: random.Random, event_name: str) -> str:
    if event_name in FAILURE_EVENTS:
        return rng.choices(["Failure", "Success", "Unknown"], weights=[80, 15, 5])[0]
    if event_name in SUCCESS_BIAS_EVENTS:
        return rng.choices(["Success", "Failure", "Unknown"], weights=[92, 6, 2])[0]
    return rng.choices(["Success", "Failure", "Unknown"], weights=[85, 10, 5])[0]


def pick_target(rng: random.Random, event_name: str, workload: str, user: dict) -> str:
    """Return a plausible target resource string."""
    if workload in ("SharePoint", "OneDrive"):
        site = rng.choice(SHAREPOINT_SITES)
        fname = rng.choice(FILE_NAMES)
        return f"{site}/Documents/{fname}"
    if workload == "Exchange":
        if "InboxRule" in event_name or "UpdateInboxRules" == event_name:
            return rng.choice(INBOX_RULE_NAMES)
        return user["email"]
    if workload == "Okta":
        if "app." in event_name:
            return rng.choice(TARGET_APPS)
        return user["email"]
    if workload == "AzureActiveDirectory":
        if "role" in event_name.lower():
            return rng.choice(["Global Administrator", "Security Reader",
                               "Exchange Administrator", "User Administrator",
                               "SharePoint Administrator", "Billing Administrator"])
        if "application" in event_name.lower() or "service principal" in event_name.lower():
            return rng.choice(TARGET_APPS)
        return user["email"]
    return user["email"]


def build_raw_json(
    rng: random.Random,
    timestamp_str: str,
    user: dict,
    event_name: str,
    workload: str,
    ip: str,
    ua: str,
    outcome: str,
    target: str,
) -> str:
    """Build a realistic nested JSON blob depending on workload."""
    city_name, country, lat, lon = rng.choice(CITIES)
    session_id = str(uuid.UUID(int=rng.getrandbits(128), version=4))
    correlation_id = str(uuid.UUID(int=rng.getrandbits(128), version=4))
    request_id = str(uuid.UUID(int=rng.getrandbits(128), version=4))

    # Shared envelope
    raw: dict = {
        "Id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        "CreationTime": timestamp_str,
        "RecordType": RECORD_TYPES.get(workload, 0),
        "Operation": event_name,
        "OrganizationId": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        "UserType": rng.choice([0, 2, 4]),  # 0=Regular, 2=Admin, 4=ServicePrincipal
        "Workload": workload,
        "ResultStatus": outcome,
        "UserId": user["email"],
        "ClientIP": ip,
    }

    if workload == "Okta":
        raw = _okta_blob(rng, raw, timestamp_str, user, event_name, ip, ua,
                         outcome, target, city_name, country, lat, lon,
                         session_id, request_id)
    elif workload == "AzureActiveDirectory":
        raw = _aad_blob(rng, raw, user, event_name, ip, ua, outcome, target,
                        city_name, country, lat, lon, session_id,
                        correlation_id, request_id)
    elif workload == "Exchange":
        raw = _exchange_blob(rng, raw, user, event_name, ua, target,
                             session_id, correlation_id)
    elif workload in ("SharePoint", "OneDrive"):
        raw = _sharepoint_blob(rng, raw, user, event_name, ua, target,
                               city_name, country, correlation_id)
    else:
        raw["UserAgent"] = ua
        raw["CorrelationId"] = correlation_id

    return json.dumps(raw, separators=(",", ":"))


def _okta_blob(rng, raw, ts, user, event, ip, ua, outcome, target,
               city, country, lat, lon, session_id, request_id):
    raw.update({
        "uuid": raw.pop("Id"),
        "published": ts,
        "eventType": event,
        "version": "0",
        "severity": rng.choice(["INFO", "INFO", "INFO", "WARN", "ERROR"]),
        "legacyEventType": event.replace(".", "_"),
        "displayMessage": event.replace(".", " ").replace("_", " ").title(),
        "actor": {
            "id": user["id"],
            "type": "User",
            "alternateId": user["email"],
            "displayName": user["display"],
        },
        "client": {
            "userAgent": {
                "rawUserAgent": ua,
                "os": rng.choice(OS_LIST),
                "browser": rng.choice(BROWSER_LIST),
            },
            "zone": rng.choice(["Default", "Corporate", "BlockedIPs", "LegacyVPN"]),
            "device": rng.choice(["Computer", "Mobile", "Unknown"]),
            "ipAddress": ip,
            "geographicalContext": {
                "city": city,
                "state": None,
                "country": country,
                "postalCode": None,
                "geolocation": {"lat": round(lat + rng.uniform(-0.05, 0.05), 4),
                                "lon": round(lon + rng.uniform(-0.05, 0.05), 4)},
            },
        },
        "outcome": {
            "result": outcome.upper(),
            "reason": None if outcome == "Success" else rng.choice([
                "INVALID_CREDENTIALS", "MFA_CHALLENGE_FAILED",
                "ACCOUNT_LOCKED", "NETWORK_ZONE_BLOCKED",
                "VERIFICATION_FAILED",
            ]),
        },
        "target": [
            {
                "id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
                "type": "AppInstance" if "app." in event else "User",
                "alternateId": target,
                "displayName": target,
            }
        ],
        "transaction": {
            "type": "WEB",
            "id": request_id,
        },
        "debugContext": {
            "debugData": {
                "requestId": request_id,
                "dtHash": f"{rng.getrandbits(64):016x}",
                "requestUri": f"/api/v1/authn{'/' + rng.choice(['factors','verify','cancel']) if rng.random() < 0.3 else ''}",
                "url": f"/app/{rng.choice(['office365','salesforce','aws_console','slack'])}/{rng.getrandbits(40):010x}/sso/saml",
            }
        },
        "authenticationContext": {
            "authenticationProvider": rng.choice(["FACTOR_PROVIDER", "OKTA_AUTHENTICATION_PROVIDER", "ACTIVE_DIRECTORY"]),
            "authenticationStep": rng.randint(0, 2),
            "externalSessionId": session_id,
            "interface": rng.choice(["Okta Sign-In Page", "SAML 2.0", "OIDC", None]),
        },
        "securityContext": {
            "asNumber": rng.randint(1000, 65000),
            "asOrg": rng.choice(["Microsoft Corporation", "Amazon.com Inc.",
                                 "Google LLC", "Cloudflare Inc.",
                                 "Akamai Technologies", "Level 3 Communications"]),
            "isp": rng.choice(["Microsoft Azure", "Amazon AWS", "Google Cloud",
                               "Comcast Cable", "AT&T Services", "BT"]),
            "domain": user["domain"],
            "isProxy": rng.random() < 0.08,
        },
    })
    # Remove M365-only keys
    for k in ("RecordType", "Operation", "OrganizationId", "UserType",
              "Workload", "ResultStatus", "UserId", "ClientIP"):
        raw.pop(k, None)
    return raw


def _aad_blob(rng, raw, user, event, ip, ua, outcome, target,
              city, country, lat, lon, session_id, correlation_id, request_id):
    raw.update({
        "AzureActiveDirectoryEventType": rng.choice([0, 1]),
        "ExtendedProperties": [
            {"Name": "UserAgent", "Value": ua},
            {"Name": "RequestType", "Value": rng.choice(["OAuth2:Authorize", "OAuth2:Token", "Login:login", "SAS:EndAuth"])},
            {"Name": "ResultStatusDetail", "Value": "Success" if outcome == "Success" else rng.choice(["UserStrongAuthClientAuthNRequired", "InvalidPassword", "MFARequired", "BlockedByConditionalAccess"])},
            {"Name": "UserAuthenticationMethod", "Value": rng.choice(AUTH_METHODS)},
        ],
        "ModifiedProperties": [],
        "Actor": [
            {"ID": user["id"], "Type": 0},
            {"ID": user["email"], "Type": 5},
            {"ID": user["display"], "Type": 1},
        ],
        "ActorContextId": raw["OrganizationId"],
        "InterSystemsId": correlation_id,
        "IntraSystemId": request_id,
        "SupportTicketId": "",
        "Target": [
            {"ID": str(uuid.UUID(int=rng.getrandbits(128), version=4)), "Type": 0},
            {"ID": target, "Type": 5},
        ],
        "TargetContextId": raw["OrganizationId"],
        "ApplicationId": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        "DeviceProperties": [
            {"Name": "OS", "Value": rng.choice(OS_LIST)},
            {"Name": "BrowserType", "Value": rng.choice(BROWSER_LIST)},
            {"Name": "IsCompliantAndManaged", "Value": rng.choice(["True", "False"])},
            {"Name": "SessionId", "Value": session_id},
        ],
        "IpAddress": ip,
        "GeoLocation": {
            "City": city,
            "Country": country,
            "Latitude": round(lat + rng.uniform(-0.05, 0.05), 4),
            "Longitude": round(lon + rng.uniform(-0.05, 0.05), 4),
        },
        "UserAgent": ua,
        "ErrorNumber": 0 if outcome == "Success" else rng.choice([50126, 50053, 50076, 53003, 530032]),
    })
    return raw


def _exchange_blob(rng, raw, user, event, ua, target, session_id, correlation_id):
    raw.update({
        "MailboxOwnerUPN": user["email"],
        "MailboxOwnerSid": f"S-1-5-21-{rng.randint(1000000,9999999)}-{rng.randint(1000000,9999999)}-{rng.randint(1000000,9999999)}-{rng.randint(1000,9999)}",
        "MailboxGuid": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        "LogonType": rng.choice([0, 1, 2]),  # 0=Owner, 1=Admin, 2=Delegate
        "ExternalAccess": rng.random() < 0.05,
        "InternalLogonType": 0,
        "LogonUserSid": f"S-1-5-21-{rng.randint(1000000,9999999)}-{rng.randint(1000000,9999999)}-{rng.randint(1000000,9999999)}-{rng.randint(1000,9999)}",
        "ClientInfoString": ua[:80] if ua else "",
        "ClientProcessName": rng.choice(["OUTLOOK.EXE", "w3wp.exe", "Microsoft.Exchange.WebServices", ""]),
        "SessionId": session_id,
        "CorrelationId": correlation_id,
    })
    if "InboxRule" in event or event == "UpdateInboxRules":
        raw["OperationProperties"] = [
            {"Name": "RuleName", "Value": target},
            {"Name": "RuleCondition", "Value": rng.choice([
                "From Contains '@'", "Subject Contains 'invoice'",
                "Body Contains 'password'", "HasAttachment Equals 'true'",
            ])},
            {"Name": "RuleActions", "Value": rng.choice([
                "MoveToFolder:Deleted Items", "ForwardTo:personal@gmail.com",
                "Delete", "MarkAsRead, MoveToFolder:Archive",
            ])},
        ]
    if event == "MailItemsAccessed":
        raw["Folders"] = [{"Path": rng.choice(["\\Inbox", "\\Sent Items", "\\Drafts", "\\Archive"]),
                           "FolderCount": rng.randint(1, 50)}]
        raw["OperationCount"] = rng.randint(1, 200)
    return raw


def _sharepoint_blob(rng, raw, user, event, ua, target, city, country, correlation_id):
    parts = target.rsplit("/", 1)
    site_url = parts[0] if len(parts) > 1 else target
    file_name = parts[1] if len(parts) > 1 else ""
    raw.update({
        "SiteUrl": site_url,
        "SourceRelativeUrl": "Shared Documents",
        "SourceFileName": file_name,
        "ObjectId": target,
        "UserAgent": ua,
        "CorrelationId": correlation_id,
        "EventSource": "SharePoint",
        "ItemType": "File" if file_name else "Folder",
        "ListItemUniqueId": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        "Site": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        "WebId": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        "HighPriorityMediaProcessing": False,
        "SensitivityLabelId": "" if rng.random() < 0.7 else str(uuid.UUID(int=rng.getrandbits(128), version=4)),
    })
    if "Sharing" in event or "Link" in event:
        raw["TargetUserOrGroupName"] = f"external.user@{'gmail.com' if rng.random() < 0.5 else 'yahoo.com'}"
        raw["TargetUserOrGroupType"] = "Guest"
    return raw


# ---------------------------------------------------------------------------
# Main generation loop
# ---------------------------------------------------------------------------

def generate(args: argparse.Namespace) -> None:
    rng = random.Random(args.seed)
    users = build_user_pool(rng, count=50)

    # Pre-compute brute-force target users (10 % of pool get most failures)
    brute_force_users = users[:max(1, len(users) // 10)]

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=args.days)
    span_seconds = int((now - start).total_seconds())

    # Pre-sort random timestamps so rows are chronological
    print(f"[*] Generating {args.rows:,} timestamp offsets …", file=sys.stderr)
    offsets = sorted(rng.randint(0, span_seconds) for _ in range(args.rows))

    columns = [
        "Timestamp", "UserId", "EventName", "Workload",
        "ClientIP", "UserAgent", "Outcome", "TargetResource", "Raw",
    ]

    print(f"[*] Writing {args.rows:,} rows to {args.output} …", file=sys.stderr)
    written = 0
    report_every = max(1, args.rows // 20)

    with open(args.output, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(columns)

        for offset in offsets:
            ts = start + timedelta(seconds=offset)
            ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{rng.randint(0,999999):06d}Z"

            idx = rng.choices(range(len(EVENT_NAMES)), weights=EVENT_WEIGHTS, k=1)[0]
            event_name = EVENT_NAMES[idx]
            workload = EVENT_LOADS[idx]

            # Cluster failures around brute-force users
            if event_name in FAILURE_EVENTS and rng.random() < 0.7:
                user = rng.choice(brute_force_users)
            else:
                user = rng.choice(users)

            ip = pick_ip(rng)
            ua = rng.choice(USER_AGENTS)
            outcome = pick_outcome(rng, event_name)
            target = pick_target(rng, event_name, workload, user)

            raw_json = build_raw_json(
                rng, ts_str, user, event_name, workload,
                ip, ua, outcome, target,
            )

            writer.writerow([
                ts_str, user["email"], event_name, workload,
                ip, ua, outcome, target, raw_json,
            ])

            written += 1
            if written % report_every == 0:
                pct = written * 100 // args.rows
                print(f"    … {pct:3d}% ({written:,} / {args.rows:,})", file=sys.stderr)

    print(f"[✓] Done — wrote {written:,} rows to {args.output}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(
        description="Generate large CSV files mimicking parsed Microsoft 365 / Okta unified audit logs.",
    )
    p.add_argument("--rows", "-r", type=int, default=1_000_000,
                   help="Number of log rows to generate (default: 1 000 000)")
    p.add_argument("--output", "-o", type=str, default="sample_logs.csv",
                   help="Output CSV file path (default: sample_logs.csv)")
    p.add_argument("--days", "-d", type=int, default=30,
                   help="Spread timestamps over this many past days (default: 30)")
    p.add_argument("--seed", "-s", type=int, default=None,
                   help="Random seed for reproducible output")
    generate(p.parse_args())


if __name__ == "__main__":
    main()
