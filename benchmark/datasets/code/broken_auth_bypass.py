def admin_action(req):
    # Insecure client-side header trust
    if req.headers.get("X-Is-Admin") == "true":
        return "Admin access granted"
    return "Forbidden"
