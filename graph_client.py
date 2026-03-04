# graph_client.py — Fetches data from Microsoft Entra ID via Microsoft Graph API
import os
import requests
from dotenv import load_dotenv

load_dotenv()

TENANT_ID = os.getenv("ENTRA_TENANT_ID")
CLIENT_ID = os.getenv("ENTRA_CLIENT_ID")
CLIENT_SECRET = os.getenv("ENTRA_CLIENT_SECRET")


class EntraGraphClient:
    """Client to fetch Entra ID data from a target tenant using Graph API."""

    def __init__(self):
        self.token = None
        self.base_url = "https://graph.microsoft.com/v1.0"
        self.beta_url = "https://graph.microsoft.com/beta"

    def _get_token(self):
        """Authenticate using OAuth 2.0 client credentials flow."""
        if self.token:
            return self.token
        token_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
        response = requests.post(token_url, data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "https://graph.microsoft.com/.default"
        })
        response.raise_for_status()
        self.token = response.json()["access_token"]
        return self.token

    def _headers(self):
        return {"Authorization": f"Bearer {self._get_token()}"}

    def _get(self, endpoint, beta=False):
        """Make a GET request to Graph API, handling pagination."""
        base = self.beta_url if beta else self.base_url
        url = f"{base}{endpoint}"
        all_results = []
        while url:
            resp = requests.get(url, headers=self._headers())
            resp.raise_for_status()
            data = resp.json()
            all_results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
        return all_results

    # ── ORGANIZATION ──────────────────────────────────────────

    def get_organization(self):
        """Get the tenant/organization info (name, id)."""
        url = f"{self.base_url}/organization"
        resp = requests.get(url, headers=self._headers())
        resp.raise_for_status()
        orgs = resp.json().get("value", [])
        return orgs[0] if orgs else {}

    # ── USERS ─────────────────────────────────────────────────

    def get_users(self):
        """Get all users with security-relevant properties."""
        return self._get(
            "/users?$select=id,displayName,userPrincipalName,accountEnabled,"
            "userType,createdDateTime,signInActivity,assignedLicenses,onPremisesSyncEnabled"
        )

    def get_guest_users(self):
        """Get all guest/external users."""
        return self._get("/users?$filter=userType eq 'Guest'&$select=id,displayName,userPrincipalName,createdDateTime")

    # ── ROLES ─────────────────────────────────────────────────

    def get_directory_roles(self):
        """Get all activated directory roles and their members."""
        roles = self._get("/directoryRoles?$expand=members")
        result = []
        for role in roles:
            members = role.get("members", [])
            result.append({
                "roleDisplayName": role["displayName"],
                "roleId": role["id"],
                "memberCount": len(members),
                "members": [{
                    "displayName": m.get("displayName", "Unknown"),
                    "userPrincipalName": m.get("userPrincipalName", "N/A"),
                    "id": m["id"],
                    "#odata.type": m.get("@odata.type", "unknown")
                } for m in members]
            })
        return result

    def get_global_admins(self):
        """Get specifically Global Administrator role members."""
        roles = self.get_directory_roles()
        for role in roles:
            if role["roleDisplayName"] == "Global Administrator":
                return role
        return {"roleDisplayName": "Global Administrator", "members": [], "memberCount": 0}

    # ── CONDITIONAL ACCESS ────────────────────────────────────

    def get_conditional_access_policies(self):
        """Get all Conditional Access policies."""
        return self._get("/identity/conditionalAccess/policies")

    # ── APPLICATIONS & SERVICE PRINCIPALS ─────────────────────

    def get_app_registrations(self):
        """Get all app registrations with credentials info."""
        return self._get(
            "/applications?$select=id,appId,displayName,passwordCredentials,"
            "keyCredentials,requiredResourceAccess,signInAudience"
        )

    def get_service_principals(self):
        """Get all service principals (enterprise apps)."""
        return self._get(
            "/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,"
            "accountEnabled,appRoleAssignedTo"
        )

    def get_service_principal_app_roles(self):
        """Get app role assignments for all service principals."""
        sps = self._get("/servicePrincipals?$select=id,displayName,appId")
        results = []
        for sp in sps:
            try:
                assignments = self._get(f"/servicePrincipals/{sp['id']}/appRoleAssignments")
                if assignments:
                    results.append({
                        "displayName": sp["displayName"],
                        "appId": sp["appId"],
                        "appRoleAssignments": assignments
                    })
            except Exception:
                pass
        return results

    # ── GROUPS ────────────────────────────────────────────────

    def get_privileged_groups(self):
        """Get groups that are role-assignable (can hold Entra roles)."""
        return self._get("/groups?$filter=isAssignableToRole eq true&$select=id,displayName,membershipRule,membershipRuleProcessingState,members")

    # ── AUTHENTICATION METHODS ────────────────────────────────

    def get_auth_methods_policy(self):
        """Get authentication methods policy (what MFA methods are enabled)."""
        url = f"{self.base_url}/policies/authenticationMethodsPolicy"
        resp = requests.get(url, headers=self._headers())
        resp.raise_for_status()
        return resp.json()

    # ── LOGS ──────────────────────────────────────────────────

    def get_recent_sign_ins(self, top=50):
        """Get recent sign-ins (requires AuditLog.Read.All)."""
        return self._get(f"/auditLogs/signIns?$top={top}&$orderby=createdDateTime desc")

    def get_risky_users(self):
        """Get users flagged as risky by Identity Protection."""
        return self._get("/identityProtection/riskyUsers")

    # ── NAMED LOCATIONS ───────────────────────────────────────

    def get_named_locations(self):
        """Get named locations used in CA policies."""
        return self._get("/identity/conditionalAccess/namedLocations")

    # ── FULL AUDIT ────────────────────────────────────────────

    def get_full_audit_data(self):
        """Collect all data needed for a comprehensive security audit."""
        print("Fetching full audit data...")
        data = {
            "users": self.get_users(),
            "guest_users": self.get_guest_users(),
            "directory_roles": self.get_directory_roles(),
            "conditional_access_policies": self.get_conditional_access_policies(),
            "app_registrations": self.get_app_registrations(),
            "service_principals": self.get_service_principals(),
            "auth_methods_policy": self.get_auth_methods_policy(),
            "named_locations": self.get_named_locations(),
        }
        print(f"  {len(data['users'])} users, {len(data['directory_roles'])} roles, "
              f"{len(data['conditional_access_policies'])} CA policies, "
              f"{len(data['service_principals'])} service principals")
        return data


if __name__ == "__main__":
    client = EntraGraphClient()
    print(f"\nTenant: {client.get_organization().get('displayName', 'Unknown')}")
    admins = client.get_global_admins()
    print(f"Global Admins ({admins['memberCount']}):")
    for m in admins.get("members", []):
        print(f"  - {m['displayName']} ({m['userPrincipalName']})")
