"""
=============================================================================
SSO Settings - django-auth-adfs with Azure AD (Entra ID)
=============================================================================

Migration from: django-auth-ldap
Migration to:   django-auth-adfs (OIDC/OAuth2 against Azure AD)

ANSWERS TO YOUR QUESTIONS:
---------------------------------------------------------------------------

1. SERVER NAME / login.microsoftonline.com
   ----------------------------------------
   YES — even in a corporate bank, the server is still
   "login.microsoftonline.com" for standard Azure AD / Entra ID tenants.

   EXCEPTIONS (ask your cloud team which one):
   - Azure Government:  login.microsoftonline.us
   - Azure China (21V): login.chinacloudapi.cn
   - Azure Germany:     login.microsoftonline.de  (mostly deprecated)

   Your bank's tenant isolation comes from the TENANT_ID, not the domain.
   All tenants share the same login endpoint.
   If your bank uses a CUSTOM DOMAIN (e.g. login.yourbank.com), that's
   typically a vanity redirect — the actual IdP is still Microsoft's.

2. OIDC vs SAML
   ----------------------------------------
   django-auth-adfs uses OIDC (OpenID Connect) / OAuth2, NOT SAML.
   It speaks the authorization_code flow (browser SSO) and can also
   validate Bearer access tokens (for DRF API calls).
   This is the modern standard — SAML is legacy. OIDC is what you want.

3. CALLBACK URL
   ----------------------------------------
   django-auth-adfs defaults to /oauth2/callback/.
   You want /oidc/callback/ — we override that below by mounting
   the urls under 'oidc/' prefix instead of 'oauth2/'.
   Tell your cloud team the redirect URI is:
       https://your-domain.com/oidc/callback/

4. SESSION vs TOKEN AUTHENTICATION (for DRF)
   ----------------------------------------
   Use BOTH. Here's why:

   SessionAuthentication:
     - Browser-based users who log in via the OIDC redirect flow
     - Django admin, any server-rendered templates
     - The SSO callback creates a Django session automatically

   AdfsAccessTokenAuthentication (Bearer token):
     - API consumers (scripts, SPAs, mobile apps, service-to-service)
     - Client sends: Authorization: Bearer <azure-ad-access-token>
     - django-auth-adfs validates the token against Azure AD's JWKS
     - No Django session needed

   For a bank: you almost certainly need both. Your internal users
   hit the browser SSO flow (session), and any API integrations or
   frontend SPAs send Bearer tokens.
=============================================================================
"""

import os
from datetime import timedelta

# ---------------------------------------------------------------------------
# 1. INSTALLED APPS — add django_auth_adfs, remove django_auth_ldap
# ---------------------------------------------------------------------------
# In your main settings.py, update INSTALLED_APPS:
#
# REMOVE:
#   'django_auth_ldap',
#
# ADD:
#   'django_auth_adfs',

# ---------------------------------------------------------------------------
# 2. AZURE AD CREDENTIALS (from your cloud team)
# ---------------------------------------------------------------------------
# NEVER hardcode these. Use environment variables or a vault.

AZURE_CLIENT_ID = os.environ.get("AZURE_AD_CLIENT_ID", "")
AZURE_CLIENT_SECRET = os.environ.get("AZURE_AD_CLIENT_SECRET", "")
AZURE_TENANT_ID = os.environ.get("AZURE_AD_TENANT_ID", "")

# ---------------------------------------------------------------------------
# 3. AUTH_ADFS CONFIGURATION
# ---------------------------------------------------------------------------
AUTH_ADFS = {
    # ── Azure AD connection ──────────────────────────────────────────────
    # Standard Azure AD / Entra ID. For sovereign clouds, change this:
    #   Government: "login.microsoftonline.us"
    #   China:      "login.chinacloudapi.cn"
    "SERVER": "login.microsoftonline.com",
    "TENANT_ID": AZURE_TENANT_ID,
    # ── App registration ─────────────────────────────────────────────────
    "CLIENT_ID": AZURE_CLIENT_ID,
    "CLIENT_SECRET": AZURE_CLIENT_SECRET,
    "AUDIENCE": AZURE_CLIENT_ID,  # For Azure AD, audience = client_id
    "RELYING_PARTY_ID": AZURE_CLIENT_ID,  # Same as client_id for Azure AD
    # ── User claim mapping (replaces AUTH_LDAP_USER_ATTR_MAP) ────────────
    # Maps JWT claims → Django User model fields
    "CLAIM_MAPPING": {
        "first_name": "given_name",
        "last_name": "family_name",
        "email": "mail",  # or "upn" depending on your Azure config
    },
    # ── Username claim ───────────────────────────────────────────────────
    # "upn" = user@yourbank.com (UserPrincipalName)
    # This replaces LDAP's uid/sAMAccountName as the unique identifier
    "USERNAME_CLAIM": "upn",
    # ── Group syncing (replaces AUTH_LDAP_MIRROR_GROUPS) ─────────────────
    # This is the equivalent of django-auth-ldap's memberOf group mirroring.
    #
    # Azure AD can send groups in two ways:
    #   "groups" claim = group Object IDs (GUIDs)
    #   "roles" claim  = App Roles you define in the App Registration
    #
    # If your cloud team configured "groups" in Token Configuration:
    "GROUPS_CLAIM": "groups",
    #
    # If they configured App Roles instead:
    # "GROUPS_CLAIM": "roles",
    # Mirror groups: when True, user's Django groups are REPLACED by
    # what's in the claim on every login. Exactly like AUTH_LDAP_MIRROR_GROUPS.
    "MIRROR_GROUPS": True,
    # Auto-create Django Group objects if they don't exist yet
    "CREATE_NEW_GROUPS": True,
    # ── Group-to-flag mapping (replaces AUTH_LDAP_USER_FLAGS_BY_GROUP) ───
    # Set is_staff / is_superuser based on Azure AD group membership.
    # Use the group NAME (not GUID) if GROUPS_CLAIM sends names,
    # or the GUID if it sends Object IDs.
    "GROUP_TO_FLAG_MAPPING": {
        "is_staff": ["App-Staff", "App-Admins"],
        "is_superuser": "App-Admins",
    },
    # ── Boolean claim mapping ────────────────────────────────────────────
    # If Azure sends specific boolean claims, map them here.
    # "BOOLEAN_CLAIM_MAPPING": {
    #     "is_staff": "user_is_staff",
    # },
    # ── User creation ────────────────────────────────────────────────────
    "CREATE_NEW_USERS": True,  # Auto-create on first SSO login
    # ── Security settings ────────────────────────────────────────────────
    "LOGIN_EXEMPT_URLS": [
        "^api/health/$",  # Health check endpoint (no auth needed)
    ],
    # Block guest/external users (important for a bank)
    "BLOCK_GUEST_USERS": True,
    # Config reload interval (seconds) — how often to re-fetch OIDC metadata
    # This handles automatic certificate rollover from Azure AD
    "CONFIG_RELOAD_INTERVAL": 1800,  # 30 minutes
    # ── Token settings ───────────────────────────────────────────────────
    # Verify token against Azure AD's JWKS endpoint
    # NEVER set this to False in production
    # "CA_BUNDLE": True,  # Use default CA bundle (or path to custom CA)
    # ── Version ──────────────────────────────────────────────────────────
    "VERSION": "v2.0",  # Use v2.0 endpoints (recommended for new setups)
}

# ---------------------------------------------------------------------------
# 4. AUTHENTICATION BACKENDS
# ---------------------------------------------------------------------------
# Replace your LDAP backend with the ADFS backends.
#
# BEFORE (LDAP):
#   AUTHENTICATION_BACKENDS = [
#       'django_auth_ldap.backend.LDAPBackend',
#       'django.contrib.auth.backends.ModelBackend',
#   ]
#
# AFTER (Azure AD SSO):
AUTHENTICATION_BACKENDS = [
    # Browser-based SSO (authorization_code flow → session)
    "django_auth_adfs.backend.AdfsAuthCodeBackend",
    # DRF API Bearer token validation
    "django_auth_adfs.backend.AdfsAccessTokenBackend",
    # Fallback: standard Django username/password (for local admin, service accounts)
    "django.contrib.auth.backends.ModelBackend",
]

# ---------------------------------------------------------------------------
# 5. DRF AUTHENTICATION CLASSES
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        # 1. Azure AD Bearer token (for API clients, SPAs, scripts)
        "django_auth_adfs.rest_framework.AdfsAccessTokenAuthentication",
        # 2. Session auth (for browser users who did the SSO flow)
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    # Throttling — important for a bank
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "20/hour",
        "user": "1000/hour",
    },
}

# ---------------------------------------------------------------------------
# 6. SESSION SETTINGS (hardened for banking)
# ---------------------------------------------------------------------------
SESSION_COOKIE_AGE = 3600  # 1 hour (shorter for bank security)
SESSION_COOKIE_SECURE = True  # HTTPS only
SESSION_COOKIE_HTTPONLY = True  # No JS access
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = True  # Extend session on activity

# CSRF hardening
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True

# ---------------------------------------------------------------------------
# 7. LOGIN / LOGOUT URLS
# ---------------------------------------------------------------------------
LOGIN_URL = "/oidc/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"

# ---------------------------------------------------------------------------
# 8. LOGGING (comprehensive for bank audit requirements)
# ---------------------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{asctime}] {levelname} {name} {module}:{lineno} | {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
        "file_auth": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": os.environ.get("AUTH_LOG_PATH", "/var/log/app/auth.log"),
            "maxBytes": 10 * 1024 * 1024,  # 10 MB
            "backupCount": 10,
            "formatter": "verbose",
        },
    },
    "loggers": {
        # django-auth-adfs internal logging
        "django_auth_adfs": {
            "handlers": ["console", "file_auth"],
            "level": "DEBUG",  # Set to INFO in production once stable
            "propagate": False,
        },
        # Our custom SSO auth module
        "sso.auth": {
            "handlers": ["console", "file_auth"],
            "level": "DEBUG",
            "propagate": False,
        },
        # DRF
        "rest_framework": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
    },
}

"""
=============================================================================
urls.py — SSO URL Configuration
=============================================================================

Maps django-auth-adfs routes under /oidc/ prefix (instead of default /oauth2/)
so the callback URL becomes /oidc/callback/ as you requested.

Tell your Azure cloud team the redirect URI is:
    https://your-domain.com/oidc/callback/
=============================================================================
"""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    # ── SSO Routes (mounted at /oidc/ instead of default /oauth2/) ───────
    # This gives you:
    #   /oidc/login/          → Redirects user to Azure AD login page
    #   /oidc/login_no_sso/   → Forces username/password prompt (skips SSO)
    #   /oidc/callback/       → Azure AD redirects back here after auth ✓
    #   /oidc/logout/         → Logs out of Django + Azure AD
    path("oidc/", include("django_auth_adfs.urls")),
    # ── DRF API Routes ───────────────────────────────────────────────────
    # DO NOT include rest_framework.urls here — it conflicts with ADFS login.
    # Instead, use the ADFS DRF urls for the browsable API login:
    path("oidc/", include("django_auth_adfs.drf_urls")),
    # ── Your API ─────────────────────────────────────────────────────────
    path("api/", include("sso_auth.urls")),
]

"""
=============================================================================
sso_auth/views.py — DRF Test & Diagnostic Endpoints
=============================================================================

These endpoints let you verify that SSO is wired up correctly end-to-end.
Use them during development and integration testing with your cloud team.

Endpoints:
    GET /api/health/             → No auth needed. Returns 200 if app is alive.
    GET /api/auth/status/        → Requires auth. Shows who you are.
    GET /api/auth/groups/        → Requires auth. Shows your groups & permissions.
    GET /api/auth/token-debug/   → Requires auth. Shows decoded token claims.
    GET /api/auth/sso-config/    → Staff only. Shows SSO config (redacted).
=============================================================================
"""

import logging
from datetime import datetime, timezone

from django.conf import settings
from django.contrib.auth.models import Group
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.response import Response

logger = logging.getLogger("sso.auth")


# ---------------------------------------------------------------------------
# 1. HEALTH CHECK — no auth, no throttle
# ---------------------------------------------------------------------------
@api_view(["GET"])
@authentication_classes([])  # Skip auth entirely
@permission_classes([AllowAny])
def health_check(request):
    """
    GET /api/health/

    Simple liveness probe. Returns 200 if Django is running.
    Use this for load balancer health checks, k8s probes, etc.
    Does NOT check database or Azure AD connectivity (that's a readiness probe).
    """
    return Response(
        {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "your-app-name",
        },
        status=status.HTTP_200_OK,
    )


# ---------------------------------------------------------------------------
# 2. AUTH STATUS — verify SSO login worked
# ---------------------------------------------------------------------------
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def auth_status(request):
    """
    GET /api/auth/status/

    After SSO login, hit this endpoint to verify:
      - Your session or Bearer token is valid
      - Django recognized you as an authenticated user
      - Your user record was created/updated correctly

    Test with browser (session):
      1. Visit /oidc/login/  → redirects to Azure → back to app
      2. Visit /api/auth/status/  → should show your user info

    Test with Bearer token (cURL):
      curl -H "Authorization: Bearer <your-azure-ad-access-token>" \
           https://your-domain.com/api/auth/status/
    """
    user = request.user

    # Determine which auth method was used
    auth_method = "unknown"
    if hasattr(request, "auth") and request.auth:
        auth_method = "bearer_token"
    elif request.user.is_authenticated and request.session.session_key:
        auth_method = "session"

    data = {
        "authenticated": True,
        "auth_method": auth_method,
        "user": {
            "id": user.pk,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "is_active": user.is_active,
            "is_staff": user.is_staff,
            "is_superuser": user.is_superuser,
            "date_joined": user.date_joined.isoformat(),
            "last_login": user.last_login.isoformat() if user.last_login else None,
        },
        "groups": list(user.groups.values_list("name", flat=True)),
        "permissions": sorted(user.get_all_permissions())
        if user.is_staff
        else "hidden (staff only)",
    }

    logger.info("AUTH_STATUS_CHECK | user=%s method=%s", user.username, auth_method)
    return Response(data)


# ---------------------------------------------------------------------------
# 3. GROUP MEMBERSHIP — verify group sync (memberOf equivalent)
# ---------------------------------------------------------------------------
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def auth_groups(request):
    """
    GET /api/auth/groups/

    Shows detailed group membership — the equivalent of checking
    what django-auth-ldap's MIRROR_GROUPS synced. Use this to verify
    that Azure AD groups are being mapped to Django groups correctly.

    This is your primary debugging endpoint for the LDAP → SSO migration.
    Compare the output here with what you used to see in LDAP's memberOf.
    """
    user = request.user

    user_groups = user.groups.all()
    group_data = []
    for group in user_groups:
        perms = group.permissions.all()
        group_data.append(
            {
                "name": group.name,
                "id": group.pk,
                "permissions": [
                    f"{p.content_type.app_label}.{p.codename}" for p in perms
                ],
            }
        )

    # Also show all available groups in the system for comparison
    all_groups = Group.objects.all().values_list("name", flat=True)

    data = {
        "user": user.username,
        "group_count": len(group_data),
        "groups": group_data,
        "all_system_groups": sorted(all_groups),
        "is_staff": user.is_staff,
        "is_superuser": user.is_superuser,
        "flags_explanation": {
            "is_staff": "Set by GROUP_TO_FLAG_MAPPING in AUTH_ADFS settings",
            "is_superuser": "Set by GROUP_TO_FLAG_MAPPING in AUTH_ADFS settings",
        },
    }

    return Response(data)


# ---------------------------------------------------------------------------
# 4. TOKEN DEBUG — inspect the Azure AD claims (dev/staging only)
# ---------------------------------------------------------------------------
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def token_debug(request):
    """
    GET /api/auth/token-debug/

    Shows the claims from the Azure AD token. Useful for debugging
    claim mapping issues, seeing what groups Azure sends, etc.

    ⚠️  DISABLE THIS IN PRODUCTION or restrict to staff only.
        Token claims contain PII and security-sensitive data.
    """
    # In production, restrict this to staff
    if not settings.DEBUG and not request.user.is_staff:
        return Response(
            {"error": "This endpoint is restricted to staff in production."},
            status=status.HTTP_403_FORBIDDEN,
        )

    # django-auth-adfs stores claims on the request during authentication
    claims = {}

    # Try to get claims from the session (auth_code flow)
    if hasattr(request, "session"):
        claims = request.session.get("adfs_claims", {})

    # Try to get claims from the request (access_token flow)
    if not claims and hasattr(request, "claims"):
        claims = request.claims

    # Redact sensitive fields
    redacted_claims = {}
    sensitive_keys = {"nonce", "c_hash", "at_hash"}
    for key, value in claims.items():
        if key in sensitive_keys:
            redacted_claims[key] = "[REDACTED]"
        else:
            redacted_claims[key] = value

    data = {
        "user": request.user.username,
        "claims_source": "session"
        if request.session.get("adfs_claims")
        else "access_token",
        "claims": redacted_claims,
        "note": "These are the raw claims from Azure AD. "
        "Use 'groups' or 'roles' to verify group membership mapping.",
    }

    logger.info(
        "TOKEN_DEBUG | user=%s (staff=%s)", request.user.username, request.user.is_staff
    )
    return Response(data)


# ---------------------------------------------------------------------------
# 5. SSO CONFIG CHECK — verify settings are correct (staff only)
# ---------------------------------------------------------------------------
@api_view(["GET"])
@permission_classes([IsAdminUser])
def sso_config_check(request):
    """
    GET /api/auth/sso-config/

    Staff-only endpoint that shows the current SSO configuration
    with secrets redacted. Useful for verifying deployment config.
    """
    auth_adfs = getattr(settings, "AUTH_ADFS", {})

    # Redact secrets
    safe_config = {}
    secret_keys = {"CLIENT_SECRET"}
    for key, value in auth_adfs.items():
        if key in secret_keys:
            safe_config[key] = f"***{str(value)[-4:]}" if value else "[NOT SET]"
        elif key == "CLIENT_ID":
            safe_config[key] = f"{str(value)[:8]}..." if value else "[NOT SET]"
        else:
            safe_config[key] = value

    # Check for common misconfigurations
    issues = []
    if not auth_adfs.get("CLIENT_ID"):
        issues.append("CLIENT_ID is not set")
    if not auth_adfs.get("CLIENT_SECRET"):
        issues.append("CLIENT_SECRET is not set")
    if not auth_adfs.get("TENANT_ID"):
        issues.append("TENANT_ID is not set")
    if auth_adfs.get("VERSION") != "v2.0":
        issues.append("Consider using VERSION='v2.0' for Azure AD")
    if not auth_adfs.get("BLOCK_GUEST_USERS"):
        issues.append("BLOCK_GUEST_USERS is False — external users can log in")
    if not auth_adfs.get("MIRROR_GROUPS"):
        issues.append("MIRROR_GROUPS is False — groups won't sync from Azure AD")

    # Check authentication backends
    backends = getattr(settings, "AUTHENTICATION_BACKENDS", [])

    data = {
        "config": safe_config,
        "issues": issues if issues else "No issues detected",
        "authentication_backends": backends,
        "callback_url": "/oidc/callback/",
        "login_url": "/oidc/login/",
        "logout_url": "/oidc/logout/",
    }

    logger.info(
        "SSO_CONFIG_CHECK | user=%s issues=%d", request.user.username, len(issues)
    )
    return Response(data)


"""
=============================================================================
sso_auth/urls.py — API URL patterns
=============================================================================

    /api/health/             → Health check (no auth)
    /api/auth/status/        → Auth verification (requires login)
    /api/auth/groups/        → Group membership check (requires login)
    /api/auth/token-debug/   → Token claim inspection (staff in prod)
    /api/auth/sso-config/    → SSO config diagnostics (admin only)
=============================================================================
"""

from django.urls import path

from . import views

app_name = "sso_auth"

urlpatterns = [
    # No auth required
    path("health/", views.health_check, name="health-check"),
    # Auth required — SSO test endpoints
    path("auth/status/", views.auth_status, name="auth-status"),
    path("auth/groups/", views.auth_groups, name="auth-groups"),
    path("auth/token-debug/", views.token_debug, name="token-debug"),
    # Admin only
    path("auth/sso-config/", views.sso_config_check, name="sso-config"),
]


# cron
import logging

from cron_descriptor import ExpressionDescriptor, FormatException
from django.db import models

logger = logging.getLogger(__name__)


class Project(models.Model):
    name = models.CharField(max_length=255)
    ingestion_schedule = models.CharField(max_length=100)  # The raw cron string

    @property
    def human_readable_schedule(self):
        """
        Converts '0 0 * * *' to 'At 12:00 AM'
        """
        if not self.ingestion_schedule:
            return "No schedule defined"

        try:
            return ExpressionDescriptor(self.ingestion_schedule).get_description()
        except FormatException:
            # Log specific user-facing format issues as warnings
            logger.warning(
                f"Project {self.id} has invalid cron: {self.ingestion_schedule}"
            )
            return "Invalid cron format"
        except Exception as e:
            # Log unexpected system/library crashes as errors
            logger.error(
                f"Unexpected error parsing cron for Project {self.id}: {e}",
                exc_info=True,
            )
            return "Error parsing schedule"


from cron_descriptor import ExpressionDescriptor, FormatException
from rest_framework import serializers

from .models import Project


class ProjectSerializer(serializers.ModelSerializer):
    # This field is calculated on the fly
    readable_schedule = serializers.SerializerMethodField()

    class Meta:
        model = Project
        fields = ["id", "name", "ingestion_schedule", "readable_schedule"]

    def get_readable_schedule(self, obj):
        try:
            return ExpressionDescriptor(obj.ingestion_schedule).get_description()
        except Exception:
            return "Invalid schedule"

    # Validation logic to ensure bad crons don't enter the system
    def validate_ingestion_schedule(self, value):
        try:
            ExpressionDescriptor(value).get_description()
        except FormatException:
            raise serializers.ValidationError("This is not a valid cron expression.")
        return value


import logging

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import ProjectSerializer

# Configure logging
logger = logging.getLogger(__name__)


class CronConverterView(APIView):
    """
    Takes cron values and returns the human-readable description
    using the ProjectSerializer logic.
    """

    def post(self, request, *args, **kwargs):
        # 1. Initialize serializer with request data
        # We use partial=True so we don't need to provide 'name' etc.
        serializer = ProjectSerializer(data=request.data, partial=True)

        try:
            # 2. Validate the cron string (triggers validate_ingestion_schedule)
            if serializer.is_valid():
                # We return the validated data + the calculated readable_schedule
                return Response(
                    {
                        "cron": serializer.validated_data["ingestion_schedule"],
                        "description": serializer.data.get("readable_schedule"),
                    },
                    status=status.HTTP_200_OK,
                )

            # 3. Handle Validation Errors (e.g., malformed cron)
            logger.warning(f"Validation failed for cron input: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # 4. Critical Error Logging
            logger.error(
                f"System error during cron conversion: {str(e)}", exc_info=True
            )
            return Response(
                {"error": "An unexpected error occurred processing your request."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

# asgi.py
from channels.routing import ProtocolTypeRouter, URLRouter

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": URLRouter(
        websocket_urlpatterns
        # No auth middleware wrapping — consumer handles it
    ),
})
```

---

## Updated Complete Flow for Your OCP Setup
```
┌─────────────────────┐         ┌──────────────┐         ┌─────────────────┐
│  React SPA          │         │  Azure AD    │         │  Django API     │
│  (OCP Container 1)  │         │              │         │  (OCP Container 2)│
└─────────┬───────────┘         └──────┬───────┘         └────────┬────────┘
          │                            │                          │
          │  1. MSAL.js login ────────►│                          │
          │  ◄──── tokens (id+access) ─│                          │
          │                            │                          │
          │  2. REST: Bearer token ───────────────────────────────►│
          │     (any DRF endpoint)     │    django-auth-adfs:     │
          │                            │    - validates token      │
          │                            │    - creates user if new  │
          │                            │    - syncs groups         │
          │  ◄──────────────────────── response ──────────────────│
          │                            │                          │
          │  3. WebSocket connect ────────────────────────────────►│
          │     ws.send({type:'authenticate', token:'...'}) ─────►│
          │                            │    - validates token      │
          │                            │    - creates user if new  │
          │  ◄──── {type:'auth_success'} ─────────────────────────│
          │                            │                          │
          │  4. ws.send({query:'...'}) ──────────────────────────►│
          │                            │    OBO exchange ─────────►│ Azure AD
          │                            │    ◄──── downstream token │
          │                            │    Call Azure AI ────────►│ Azure AI
          │  ◄──── streamed results ──────────────────────────────│