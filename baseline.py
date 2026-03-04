# baseline.py — Loads clean tenant snapshot and tags objects as baseline vs new
#
# USAGE:
#   1. Export your clean tenant state (before deploying EntraGoat or any lab):
#      In PowerShell (connected to your tenant via Microsoft Graph SDK):
#
#      Get-MgUser -All | Select-Object Id, DisplayName, UserPrincipalName | ConvertTo-Json | Out-File baseline_users.json
#      Get-MgApplication -All | Select-Object Id, DisplayName, AppId | ConvertTo-Json | Out-File baseline_apps.json
#      Get-MgServicePrincipal -All | Select-Object Id, DisplayName, AppId | ConvertTo-Json | Out-File baseline_serviceprincipals.json
#      Get-MgGroup -All | Select-Object Id, DisplayName | ConvertTo-Json | Out-File baseline_groups.json
#
#   2. Place the JSON files in the same directory as this script.
#   3. app.py will automatically import and use baseline tagging.
#      If the JSON files are missing, app.py falls back to no tagging.

import json
import os

BASELINE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_baseline(filename):
    """Load a baseline JSON file and return a set of object IDs."""
    filepath = os.path.join(BASELINE_DIR, filename)
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            data = [data]
        return {item["Id"] for item in data if "Id" in item}
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"  Warning: Could not load {filepath}")
        return set()


# Load all baseline IDs at startup
BASELINE_USER_IDS = _load_baseline("baseline_users.json")
BASELINE_APP_IDS = _load_baseline("baseline_apps.json")
BASELINE_SP_IDS = _load_baseline("baseline_serviceprincipals.json")
BASELINE_GROUP_IDS = _load_baseline("baseline_groups.json")

ALL_BASELINE_IDS = BASELINE_USER_IDS | BASELINE_APP_IDS | BASELINE_SP_IDS | BASELINE_GROUP_IDS

print(f"  Baseline loaded: {len(BASELINE_USER_IDS)} users, {len(BASELINE_APP_IDS)} apps, "
      f"{len(BASELINE_SP_IDS)} service principals, {len(BASELINE_GROUP_IDS)} groups")


def tag_objects(objects, baseline_ids, id_field="id"):
    """Tag each object with _source: 'BASELINE' or 'NEW (likely EntraGoat)'."""
    tagged = []
    for obj in objects:
        obj_copy = dict(obj)
        obj_id = obj_copy.get(id_field) or obj_copy.get("Id") or obj_copy.get("id")
        if obj_id and obj_id in baseline_ids:
            obj_copy["_source"] = "BASELINE"
        else:
            obj_copy["_source"] = "NEW (likely EntraGoat)"
        tagged.append(obj_copy)
    return tagged


def tag_users(users):
    return tag_objects(users, BASELINE_USER_IDS)

def tag_apps(apps):
    return tag_objects(apps, BASELINE_APP_IDS)

def tag_service_principals(sps):
    return tag_objects(sps, BASELINE_SP_IDS)

def tag_groups(groups):
    return tag_objects(groups, BASELINE_GROUP_IDS)

def tag_roles(roles):
    """Tag role members as baseline or new."""
    tagged_roles = []
    for role in roles:
        role_copy = dict(role)
        if "members" in role_copy:
            role_copy["members"] = tag_objects(role_copy["members"], ALL_BASELINE_IDS)
        tagged_roles.append(role_copy)
    return tagged_roles

def tag_full_audit(audit_data):
    """Tag all objects in a full audit result."""
    tagged = dict(audit_data)
    if "users" in tagged:
        tagged["users"] = tag_users(tagged["users"])
    if "guest_users" in tagged:
        tagged["guest_users"] = tag_users(tagged["guest_users"])
    if "directory_roles" in tagged:
        tagged["directory_roles"] = tag_roles(tagged["directory_roles"])
    if "app_registrations" in tagged:
        tagged["app_registrations"] = tag_apps(tagged["app_registrations"])
    if "service_principals" in tagged:
        tagged["service_principals"] = tag_service_principals(tagged["service_principals"])
    return tagged
