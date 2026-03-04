# app.py — Flask web app that bridges the Chat UI, AI Foundry, and Graph API
import os
import json
from flask import Flask, render_template, request, jsonify
from azure.identity import DefaultAzureCredential
from azure.ai.projects import AIProjectClient
from graph_client import EntraGraphClient
from dotenv import load_dotenv

# Optional: baseline tagging for EntraGoat lab vs real infrastructure
# If baseline files exist, objects get tagged with _source: "BASELINE" or "NEW"
# If not, everything works normally without tagging
try:
    from baseline import (
        tag_users, tag_apps, tag_service_principals, tag_groups,
        tag_roles, tag_full_audit
    )
    BASELINE_ENABLED = True
    print("Baseline tagging enabled — objects will be tagged as BASELINE or NEW")
except ImportError:
    BASELINE_ENABLED = False
    # No-op passthrough functions
    tag_users = tag_apps = tag_service_principals = tag_groups = lambda x: x
    tag_roles = lambda x: x
    tag_full_audit = lambda x: x
    print("Baseline tagging disabled — no baseline files found (this is normal for first run)")

load_dotenv()

app = Flask(__name__)

# ── AI Foundry Setup ───────────────────────────────────────────
AI_PROJECT_ENDPOINT = os.getenv("AI_PROJECT_ENDPOINT")
AGENT_NAME = os.getenv("AGENT_NAME", "AuditAssistant")

project_client = AIProjectClient(
    endpoint=AI_PROJECT_ENDPOINT,
    credential=DefaultAzureCredential(),
)
agent = project_client.agents.get(agent_name=AGENT_NAME)
openai_client = project_client.get_openai_client()

# Graph client for target tenant
graph = EntraGraphClient()

# Store conversations per session (in-memory; resets on restart)
conversations = {}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/tenant-info", methods=["GET"])
def tenant_info():
    """Fetch the connected tenant's display name dynamically."""
    try:
        org = graph.get_organization()
        return jsonify({
            "tenant_name": org.get("displayName", "Unknown Tenant"),
            "tenant_id": org.get("id", ""),
            "connected": True,
        })
    except Exception as e:
        return jsonify({
            "tenant_name": "Disconnected",
            "tenant_id": "",
            "connected": False,
            "error": str(e),
        })


@app.route("/api/chat", methods=["POST"])
def chat():
    try:
        data = request.json
        user_message = data.get("message", "").strip()
        session_id = data.get("session_id", "default")

        if not user_message:
            return jsonify({"error": "Empty message"}), 400

        # ── Detect keywords and fetch relevant data ────────────
        # If baseline is enabled, objects are tagged with _source field
        enriched_message = user_message
        tools_used = []
        msg_lower = user_message.lower()

        if any(kw in msg_lower for kw in ["global admin", "admin", "privileged role", "who has"]):
            result = tag_roles([graph.get_global_admins()])
            enriched_message += f"\n\n[LIVE TENANT DATA - Global Admins]:\n{json.dumps(result, indent=2, default=str)}"
            tools_used.append("get_global_admins")

        if any(kw in msg_lower for kw in ["conditional access", "ca polic", "access polic"]):
            result = graph.get_conditional_access_policies()
            enriched_message += f"\n\n[LIVE TENANT DATA - Conditional Access Policies]:\n{json.dumps(result, indent=2, default=str)}"
            tools_used.append("get_conditional_access_policies")

        if any(kw in msg_lower for kw in ["guest", "external user"]):
            result = tag_users(graph.get_guest_users())
            enriched_message += f"\n\n[LIVE TENANT DATA - Guest Users]:\n{json.dumps(result, indent=2, default=str)}"
            tools_used.append("get_guest_users")

        if any(kw in msg_lower for kw in ["service principal", "enterprise app", "overprivileg"]):
            result = tag_service_principals(graph.get_service_principals())
            enriched_message += f"\n\n[LIVE TENANT DATA - Service Principals]:\n{json.dumps(result, indent=2, default=str)}"
            tools_used.append("get_service_principals")

        if any(kw in msg_lower for kw in ["app registration", "app reg", "application"]):
            result = tag_apps(graph.get_app_registrations())
            enriched_message += f"\n\n[LIVE TENANT DATA - App Registrations]:\n{json.dumps(result, indent=2, default=str)}"
            tools_used.append("get_app_registrations")

        if any(kw in msg_lower for kw in ["auth method", "mfa", "authentication method"]):
            result = graph.get_auth_methods_policy()
            enriched_message += f"\n\n[LIVE TENANT DATA - Auth Methods Policy]:\n{json.dumps(result, indent=2, default=str)}"
            tools_used.append("get_auth_methods_policy")

        if any(kw in msg_lower for kw in ["user", "all user", "list user"]):
            if "guest" not in msg_lower:
                result = tag_users(graph.get_users())
                enriched_message += f"\n\n[LIVE TENANT DATA - Users]:\n{json.dumps(result, indent=2, default=str)}"
                tools_used.append("get_users")

        if any(kw in msg_lower for kw in ["risky", "risk user", "identity protection"]):
            result = tag_users(graph.get_risky_users())
            enriched_message += f"\n\n[LIVE TENANT DATA - Risky Users]:\n{json.dumps(result, indent=2, default=str)}"
            tools_used.append("get_risky_users")

        if any(kw in msg_lower for kw in ["sign-in", "signin", "login log", "sign in log"]):
            result = graph.get_recent_sign_ins()
            enriched_message += f"\n\n[LIVE TENANT DATA - Recent Sign-Ins]:\n{json.dumps(result, indent=2, default=str)}"
            tools_used.append("get_recent_sign_ins")

        if any(kw in msg_lower for kw in ["legacy auth", "legacy protocol"]):
            result = graph.get_conditional_access_policies()
            enriched_message += f"\n\n[LIVE TENANT DATA - CA Policies (for legacy auth check)]:\n{json.dumps(result, indent=2, default=str)}"
            tools_used.append("get_conditional_access_policies")

        if any(kw in msg_lower for kw in ["permission", "dangerous permission", "app role", "privilege escalat"]):
            result = graph.get_service_principal_app_roles()
            enriched_message += f"\n\n[LIVE TENANT DATA - Service Principal Permissions]:\n{json.dumps(result, indent=2, default=str)}"
            tools_used.append("get_service_principal_permissions")

        if any(kw in msg_lower for kw in ["group", "role-assignable", "dynamic group"]):
            result = tag_groups(graph.get_privileged_groups())
            enriched_message += f"\n\n[LIVE TENANT DATA - Privileged Groups]:\n{json.dumps(result, indent=2, default=str)}"
            tools_used.append("get_privileged_groups")

        if any(kw in msg_lower for kw in ["named location", "trusted ip", "trusted location"]):
            result = graph.get_named_locations()
            enriched_message += f"\n\n[LIVE TENANT DATA - Named Locations]:\n{json.dumps(result, indent=2, default=str)}"
            tools_used.append("get_named_locations")

        if any(kw in msg_lower for kw in ["stale", "unused", "inactive", "last sign"]):
            result = tag_users(graph.get_users())
            enriched_message += f"\n\n[LIVE TENANT DATA - All Users (check for stale accounts)]:\n{json.dumps(result, indent=2, default=str)}"
            tools_used.append("get_users")

        if any(kw in msg_lower for kw in ["credential", "secret", "certificate", "expir"]):
            result = tag_apps(graph.get_app_registrations())
            enriched_message += f"\n\n[LIVE TENANT DATA - App Registrations (check credentials)]:\n{json.dumps(result, indent=2, default=str)}"
            tools_used.append("get_app_registrations")

        if any(kw in msg_lower for kw in ["full audit", "full security", "comprehensive", "scan everything", "all findings"]):
            result = tag_full_audit(graph.get_full_audit_data())
            enriched_message += f"\n\n[LIVE TENANT DATA - Full Audit]:\n{json.dumps(result, indent=2, default=str)}"
            tools_used.append("run_full_audit")

        # ── Create or reuse conversation ───────────────────────
        if session_id not in conversations:
            conv = openai_client.conversations.create(
                items=[{"type": "message", "role": "user", "content": enriched_message}],
            )
            conversations[session_id] = conv.id
        else:
            openai_client.conversations.items.create(
                conversation_id=conversations[session_id],
                items=[{"type": "message", "role": "user", "content": enriched_message}],
            )

        conv_id = conversations[session_id]

        # ── Get AI response (NO tools parameter — not allowed with agent_reference) ──
        response = openai_client.responses.create(
            conversation=conv_id,
            extra_body={"agent": {"name": agent.name, "type": "agent_reference"}},
            input="",
        )

        return jsonify({
            "reply": response.output_text,
            "tools_used": tools_used,
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/reset", methods=["POST"])
def reset_conversation():
    data = request.json
    session_id = data.get("session_id", "default")
    if session_id in conversations:
        del conversations[session_id]
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    print(f"Connected to agent: {agent.name}")
    print("Starting web server on http://localhost:5555")
    app.run(debug=True, port=5555, host="0.0.0.0")
