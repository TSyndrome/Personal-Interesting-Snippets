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


┌──────────────┐       ┌──────────────┐       ┌──────────┐
│  React SPA   │       │  Django API  │       │ Azure AD │
│  (OCP #1)    │       │  (OCP #2)    │       │          │
└──────┬───────┘       └──────┬───────┘       └────┬─────┘
       │                      │                     │
       │ 1. User clicks       │                     │
       │    "Login"           │                     │
       │                      │                     │
       │ 2. window.location = │                     │
       │    django/oidc/login │                     │
       │ ────────────────────►│                     │
       │                      │                     │
       │                      │ 3. 302 redirect ───►│
       │                      │    to Azure AD      │
       │ ◄─────────────────── │ (browser follows)   │
       │ ─────────────────────────────────────────► │
       │                      │                     │
       │                      │    4. User logs in  │
       │                      │       at Azure AD   │
       │                      │                     │
       │                      │ 5. 302 callback ◄───│
       │                      │    /oidc/callback/  │
       │ ─────────────────────────────────────────► │
       │                      │◄────────────────────│
       │                      │  ?code=abc123       │
       │                      │                     │
       │                      │ 6. Django exchanges  │
       │                      │    code for tokens  │
       │                      │    (server-to-server)│
       │                      │ ───────────────────►│
       │                      │ ◄───────────────────│
       │                      │  {access_token,     │
       │                      │   id_token,         │
       │                      │   refresh_token}    │
       │                      │                     │
       │                      │ 7. Django stores    │
       │                      │    tokens in session│
       │                      │    Creates user +   │
       │                      │    syncs groups     │
       │                      │                     │
       │ 8. 302 redirect ◄────│                     │
       │    back to React app │                     │
       │    + Set-Cookie:     │                     │
       │      sessionid=xyz   │                     │
       │                      │                     │
       │ 9. React loads,      │                     │
       │    has session cookie│                     │
       │                      │                     │
       │ 10. GET /api/stuff   │                     │
       │     Cookie: session  │                     │
       │ ────────────────────►│                     │
       │                      │ session → user      │
       │ ◄──── response ──────│                     │
       │                      │                     │
       │ 11. WebSocket        │                     │
       │     Cookie: session  │                     │
       │ ════════════════════►│                     │
       │                      │ session → user      │
       │                      │                     │
       │                      │ 12. OBO call        │
       │                      │ (has tokens in      │
       │                      │  session already)   │
       │                      │ ───────────────────►│
       │                      │ ◄── downstream token│
       │                      │ ──► Azure AI        │

// Every frontend request needs
fetch('/api/...', { credentials: 'include' })
axios.defaults.withCredentials = true;
```

And you'll fight CSRF on every non-GET DRF request. DRF's `SessionAuthentication` enforces CSRF, so you either need to fetch a CSRF token first or exempt endpoints (which is a security tradeoff).

### Problem 2: Full-Page Redirects Break SPA Experience
```
User clicks Login
  → browser leaves React entirely
  → goes to Django /oidc/login/
  → goes to Azure AD
  → comes back to Django /oidc/callback/
  → redirects back to React
  → React app re-initializes from scratch
  → any client-side state is lost
```

With MSAL.js, login happens in a popup or a redirect that MSAL manages, preserving app state.

### Problem 3: Token Refresh Is Your Problem
```
Backend-managed:                    MSAL.js frontend:
─────────────────                   ─────────────────
Access token expires                Access token expires
→ next API call fails               → acquireTokenSilent()
→ need to detect 401                → MSAL auto-refreshes
→ redirect user to                    using refresh token
  /oidc/login/ again?               → seamless, no redirect
→ or build a /refresh-token          → user notices nothing
  endpoint in Django
→ manage refresh logic yourself
```

### Problem 4: WebSocket Gets Simpler but Everything Else Gets Harder

The one advantage — WebSocket just works with the session cookie. But you're trading that for pain everywhere else.

---

## Side-by-Side Comparison
```
                          │ Backend OIDC          │ Frontend MSAL.js
──────────────────────────┼───────────────────────┼────────────────────
Login UX                  │ Full page redirects   │ Popup/redirect,
                          │ SPA state lost        │ SPA state preserved
                          │                       │
Cross-origin cookies      │ SameSite=None,        │ Not needed,
                          │ CSRF headaches        │ Bearer token in header
                          │                       │
DRF auth                  │ SessionAuthentication │ AdfsAccessTokenAuth
                          │ + CSRF middleware     │ stateless, no CSRF
                          │                       │
Token refresh             │ You build it          │ MSAL handles it
                          │                       │
WebSocket auth            │ Cookie automatic      │ First-message token
                          │                       │ (few lines of code)
                          │                       │
OBO flow                  │ Token from session    │ Token from header
                          │ (slightly simpler)    │ (slightly more explicit)
                          │                       │
Scalability               │ Sticky sessions or    │ Stateless, any
                          │ shared session store  │ replica handles any
                          │ (Redis required)      │ request
                          │                       │
Two OCP containers        │ Fighting cookies      │ Just works
                          │ across origins        │       


from datetime import datetime
from django.db.models import Q
from rest_framework import status
from rest_framework.views import APIView

# Replace 'your_app' with the actual module names in your project
from your_app.models import UserConversationHistory, Project
from your_app.serializers import UserConversationHistoryMinimalSerializer
from your_app.filters import (
    TenantAccessFilterBackend,
    TenantAdminFilterBackend,
    TenantGuidFilterBackend,
)

class UserConversationHistoryView(PaginatedAPIMixin, APIView):
    """
    API view for retrieving and filtering conversation history.
    Users see their own chats; Project Admins see all chats in their projects.
    """
    model = UserConversationHistory
    serializer_class = UserConversationHistoryMinimalSerializer
    pagination_class = APIPagination
    related_fields = ["user", "project"]

    def get_base_queryset(self):
        """
        Initial queryset with field deferral for performance.
        Removed Project-Guid header logic per user's feedback.
        """
        return UserConversationHistory.objects.defer(
            "retrieved_documents",
            "metadata",
            "conversation_thread",
            "chat_config_used",
            "chat_config_version_used",
        ).select_related(*self.related_fields)

    def filter_queryset(self, queryset):
        """
        Enforces security and handles optional filtering.
        """
        request = self.request
        
        # 1. Date Range Filtering
        created_at_start = request.query_params.get("created_at_start")
        created_at_end = request.query_params.get("created_at_end")
        queryset = self.validate_dates(created_at_start, created_at_end, queryset)

        # 2. Standardized Project/Tenant Filtering (Query Params only)
        # We check the common keys user mentioned.
        project_id = (
            request.query_params.get("project_id") or 
            request.query_params.get("project_guid") or 
            request.query_params.get("tenant_id")
        )
        if project_id:
            queryset = queryset.filter(project__guid=project_id)

        # 3. Apply standard non-tenant filter backends (e.g., Search, Sort)
        # We skip the tenant backends here because we use them manually below.
        tenant_backends = {TenantAccessFilterBackend, TenantAdminFilterBackend, TenantGuidFilterBackend}
        for backend_cls in list(self.filter_backends):
            if backend_cls not in tenant_backends:
                queryset = backend_cls().filter_queryset(request, queryset, self)

        # 4. Role-Based Access Logic (The "user Union")
        if getattr(request.user, 'is_platform_admin', False):
            return queryset

        # OWNER VIEW: Their own chats in projects they have access to
        owner_view = TenantAccessFilterBackend().filter_queryset(
            request, queryset, self
        ).filter(user=request.user)

        # ADMIN VIEW: All chats in projects they administer
        admin_view = TenantAdminFilterBackend().filter_queryset(
            request, queryset, self
        )

        # Merge results and ensure uniqueness
        return (owner_view | admin_view).distinct()

    def get(self, request, *args, **kwargs):
        try:
            # .list() is provided by PaginatedAPIMixin and calls filter_queryset()
            return self.list(request)
        except ValueError as e:
            return format_response_payload(
                success=False,
                message=str(e),
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            logger.error(f"Error retrieving conversations: {str(e)}")
            return format_response_payload(
                success=False,
                message="An unexpected error occurred.",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def validate_dates(self, start, end, queryset):
        """
        Parses date strings and applies filters. 
        Returns the modified queryset.
        """
        if start:
            try:
                start_dt = datetime.strptime(start, "%Y-%m-%d")
                queryset = queryset.filter(created_at__gte=start_dt)
            except ValueError:
                raise ValueError("Invalid created_at_start format. Use YYYY-MM-DD.")
        if end:
            try:
                end_dt = datetime.strptime(end, "%Y-%m-%d")
                queryset = queryset.filter(created_at__lte=end_dt)
            except ValueError:
                raise ValueError("Invalid created_at_end format. Use YYYY-MM-DD.")
        return queryset

from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status
from your_app.models import UserConversationHistory, Project

User = get_user_model()

class UserConversationHistorySecurityTests(APITestCase):
    def setUp(self):
        # Create Projects
        self.project_a = Project.objects.create(name="Project Alpha", mnemonic="alpha")
        self.project_b = Project.objects.create(name="Project Beta", mnemonic="beta")

        # Create Users
        self.user_owner = User.objects.create_user(username="owner", password="password")
        self.user_stranger = User.objects.create_user(username="stranger", password="password")
        self.user_admin = User.objects.create_user(username="admin", password="password")

        # Setup User Permissions (Assuming custom attributes used in backends)
        self.user_owner.tenant_access_mnemonics = ["alpha"]
        self.user_owner.save()
        
        self.user_admin.tenant_admin_mnemonics = ["alpha"]
        self.user_admin.save()

        # Create Conversations
        self.convo_owner = UserConversationHistory.objects.create(
            user=self.user_owner, project=self.project_a, preview_title="Owner's Chat"
        )
        self.convo_other = UserConversationHistory.objects.create(
            user=self.user_stranger, project=self.project_a, preview_title="Stranger's Chat"
        )

        self.url = reverse('conversation-history-list') # Update with your actual URL name

    def test_owner_sees_only_own_chats(self):
        """Verify a standard user cannot see others' chats in the same project."""
        self.client.login(username="owner", password="password")
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should see their own chat, but NOT the stranger's chat
        results = response.data.get('results', [])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['id'], self.convo_owner.id)

    def test_admin_sees_all_chats_in_project(self):
        """Verify a project admin can see all chats within their project."""
        self.client.login(username="admin", password="password")
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Admin should see both conversations in Project Alpha
        results = response.data.get('results', [])
        self.assertEqual(len(results), 2)

    def test_idor_prevention_via_query_param(self):
        """Verify that passing a specific user ID doesn't leak data."""
        self.client.login(username="owner", password="password")
        # Attempting to filter specifically for the other user's ID
        response = self.client.get(f"{self.url}?user={self.user_stranger.id}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should return empty or only their own (depending on backend), 
        # but NEVER the stranger's data.
        for item in response.data.get('results', []):
            self.assertNotEqual(item['id'], self.convo_other.id)

    def test_project_filter_standardization(self):
        """Verify ?project_id query parameter works (user's suggestion)."""
        self.client.login(username="admin", password="password")
        response = self.client.get(f"{self.url}?project_id={self.project_a.guid}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(all(r['project'] == self.project_a.id for r in response.data.get('results', [])))

    def test_invalid_date_format_returns_400(self):
        """Ensure date validation logic correctly triggers a 400 error."""
        self.client.login(username="owner", password="password")
        response = self.client.get(f"{self.url}?created_at_start=invalid-date")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


#claude
"""
Rewritten UserConversationHistoryView

CRITICAL ANALYSIS OF user'S REVIEW COMMENTS
==============================================

COMMENT 1: "Why is there data being stored in headers? ... The proper way to
add a filter to a REST endpoint is with a query parameter."

    VERDICT: ✅ Agree. Using headers for filtering is an anti-pattern. HTTP
    headers are for metadata (auth tokens, content-type, caching directives),
    not business-level filtering. Moved project_guid to a query parameter to
    align with REST conventions and the existing `created_at_start`/`created_at_end`
    params which already use query parameters. This also matches the codebase
    convention user references: `request.params["tenant_id"]`.

COMMENT 2: "Why are we checking if the user has permission to view the project
that they are filtering on, when we are also filtering the queryset according
to projects the user has appropriate permissions on? This is redundant with
the filterbackend."

    VERDICT: ✅ Mostly agree, with a nuance. The permission check IS redundant
    if the filter backends already constrain the queryset to accessible projects.
    A user filtering by a project_guid they can't access will simply get an empty
    result set — the filter backend ensures no unauthorized data leaks.

    TRADE-OFF: The original code would raise a 403 if you requested a project
    you can't see. The filter-backend-only approach returns 200 with empty results.
    This is actually *better* from a security standpoint — returning 403 confirms
    the resource exists (information leakage). Returning empty results reveals
    nothing. So removing the explicit permission check is both simpler and more
    secure.

COMMENT 3: "We want users to be able to see two kinds of conversations:
1. their own conversations in tenants they are users on
2. all conversations of projects that they administrate"

    VERDICT: ✅ Agree on the business requirement, with refinements to the
    proposed implementation. user's suggested code does the union correctly:
        user_queryset | admin_queryset
    However, we should be mindful of:

    a) The `.distinct()` is necessary since a user who is both a tenant member
       AND an admin of a project could get duplicate rows from the union.

    b) The original `get_base_queryset` was doing `.defer()` on heavy fields —
       this optimization must be preserved on the base queryset BEFORE it gets
       passed to the filter backends, so both branches benefit from it.

    c) user suggests putting this in `filter_queryset()` rather than
       `get_base_queryset()`. This is correct — `get_base_queryset` in the mixin
       is meant for basic queryset setup (model selection, defer, select_related),
       while `filter_queryset` is where access-control filtering belongs. The
       mixin's `list()` method calls `get_base_queryset()` then `filter_queryset()`,
       so the access control union should live in `filter_queryset`.

ADDITIONAL ISSUES FOUND IN ORIGINAL CODE
=========================================

1. `model = None` — The PaginatedAPIMixin explicitly raises ImproperlyConfigured
   if model is None (line 73-74 in the mixin). Setting this to None and then
   overriding get_base_queryset to avoid the check is fragile. We should set
   the model explicitly.

2. `_validate_dates` mutates via queryset parameter but the method name suggests
   validation only. Renamed to `_apply_date_filters` for clarity, and it now
   returns the filtered queryset explicitly (functional style, no hidden mutation).

3. The original `get_base_queryset` mixed access control (project_guid permission
   check) with query filtering (date ranges). These are separate concerns:
   - Access control → filter_queryset (what CAN you see)
   - Query filtering → get_base_queryset or the mixin's filter pipeline (what
     do you WANT to see)
"""

from datetime import datetime
import logging

from rest_framework import status
from rest_framework.views import APIView

# These imports would come from your project — kept as references
# from rag_search.models import UserConversationHistory, Project
# from rag_search.serializers import UserConversationHistoryMinimalSerializer
# from rag_search.pagination import APIPagination
# from rag_search.permissions import TenantAccessFilterBackend, TenantAdminFilterBackend
# from rag_search.constants import (
#     USER_CONVERSATION_HISTORY_SUPPORTED_FILTERS,
#     USER_CONVERSATION_HISTORY_SORT_FIELD_MAP,
#     DEFAULT_API_SORT_FIELD,
#     DEFAULT_SORT_DIRECTION,
# )
# from rag_search.utils import format_response_payload
# from rag_search.mixins import PaginatedAPIMixin

logger = logging.getLogger(__name__)


class UserConversationHistoryView(PaginatedAPIMixin, APIView):
    """
    API view for retrieving and filtering conversation history.

    Access model:
        - Users see their own conversations within tenants they belong to.
        - Admins see ALL conversations for projects they administrate.
        These two sets are unioned and deduplicated.

    Supports filtering by:
        - project_guid  (query parameter)
        - created_at_start  (query parameter, format: YYYY-MM-DD)
        - created_at_end    (query parameter, format: YYYY-MM-DD)

    Sorting and pagination are handled by PaginatedAPIMixin.
    """

    model = UserConversationHistory
    serializer_class = UserConversationHistoryMinimalSerializer
    pagination_class = APIPagination
    filter_definitions = USER_CONVERSATION_HISTORY_SUPPORTED_FILTERS
    sort_config_map = USER_CONVERSATION_HISTORY_SORT_FIELD_MAP
    default_sort_key = DEFAULT_API_SORT_FIELD
    default_sort_direction = DEFAULT_SORT_DIRECTION
    related_fields = ["user", "project"]

    # ------------------------------------------------------------------ #
    #  Queryset construction
    # ------------------------------------------------------------------ #

    def get_base_queryset(self):
        """
        Return the base queryset with performance optimizations.

        Heavy fields that the list/history UI does not need are deferred.
        Access-control filtering is intentionally NOT done here — that
        belongs in filter_queryset() so it runs through the standard
        DRF filter-backend pipeline.
        """
        return UserConversationHistory.objects.defer(
            "retrieved_documents",
            "metadata",
            "conversation_thread",
            "chat_config_used",
            "chat_config_version_used",
        )

    def filter_queryset(self, queryset):
        """
        Apply tenant-based access control, then delegate to the mixin's
        standard filter pipeline (filter backends, sorting, etc.).

        Business rule (per user's review):
            visible = (user's own conversations in accessible tenants)
                    ∪ (all conversations in projects user administrates)

        After the access-control union, optional query-parameter filters
        (project_guid, date range) are applied.
        """
        # --- Access control: union of two permission scopes --- #
        user_queryset = TenantAccessFilterBackend().filter_queryset(
            self.request, queryset, self
        ).filter(user=self.request.user)

        admin_queryset = TenantAdminFilterBackend().filter_queryset(
            self.request, queryset, self
        )

        queryset = (user_queryset | admin_queryset).distinct()

        # --- Optional project filter (query param, NOT header) --- #
        project_guid = self.request.GET.get("project_guid")
        if project_guid:
            queryset = queryset.filter(project__guid=project_guid)
            # No explicit permission check needed — the union above already
            # guarantees the user can only see projects they have access to.
            # If the guid doesn't match any accessible project, the result
            # is simply empty (no information leakage).

        # --- Date range filters --- #
        created_at_start = self.request.GET.get("created_at_start")
        created_at_end = self.request.GET.get("created_at_end")
        queryset = self._apply_date_filters(created_at_start, created_at_end, queryset)

        # --- Delegate remaining filters (sort, etc.) to mixin --- #
        # The parent's filter_queryset applies filter_backends from settings.
        # We skip calling super().filter_queryset() here because we've already
        # applied the tenant filter backends manually above. If additional
        # generic backends (e.g. ordering) are configured in
        # DEFAULT_FILTER_BACKENDS, you may want to selectively apply those:
        #
        #   for backend in list(self.filter_backends):
        #       if backend not in (TenantAccessFilterBackend, TenantAdminFilterBackend):
        #           queryset = backend().filter_queryset(self.request, queryset, self)

        return queryset

    # ------------------------------------------------------------------ #
    #  HTTP method handler
    # ------------------------------------------------------------------ #

    def get(self, request):
        """
        Retrieve filtered RAG conversations based on provided parameters.
        If no filters are specified, return all accessible conversations.
        """
        try:
            return self.list(request)

        except ValueError as e:
            return format_response_payload(
                success=False,
                message=str(e),
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        except Exception as e:
            logger.error(f"Error retrieving conversations: {str(e)}")
            return format_response_payload(
                success=False,
                errors=str(e),
                message="An unexpected error occurred.",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    # ------------------------------------------------------------------ #
    #  Private helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _apply_date_filters(created_at_start, created_at_end, queryset):
        """
        Validate and apply date-range filters to the queryset.

        Raises ValueError with a descriptive message on invalid input,
        which the get() handler catches and returns as a 400.
        """
        date_format = "%Y-%m-%d"

        if created_at_start:
            try:
                start_date = datetime.strptime(created_at_start, date_format)
            except ValueError:
                raise ValueError(
                    "Invalid created_at_start format. Use YYYY-MM-DD."
                )
            queryset = queryset.filter(created_at__gte=start_date)

        if created_at_end:
            try:
                end_date = datetime.strptime(created_at_end, date_format)
            except ValueError:
                raise ValueError(
                    "Invalid created_at_end format. Use YYYY-MM-DD."
                )
            queryset = queryset.filter(created_at__lte=end_date)

        return queryset


#geminifrom rest_framework.views import APIView
from rest_framework import status
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class UserConversationHistoryView(PaginatedAPIMixin, APIView):
    """
    API view for retrieving and filtering conversation history.
    """
    model = UserConversationHistory 
    serializer_class = UserConversationHistoryMinimalSerializer
    pagination_class = APIPagination
    filter_definitions = USER_CONVERSATION_HISTORY_SUPPORTED_FILTERS
    sort_config_map = USER_CONVERSATION_HISTORY_SORT_FIELD_MAP
    default_sort_key = DEFAULT_API_SORT_FIELD
    default_sort_direction = DEFAULT_SORT_DIRECTION
    related_fields = ["user", "project"]

    def get_base_queryset(self):
        """
        Overrides the mixin's default method.
        We apply Trevor's permission union logic here because the custom 
        PaginatedAPIMixin does not automatically invoke filter_backends.
        """
        # 1. Base optimization
        queryset = self.model.objects.defer(
            "retrieved_documents", "metadata", "conversation_thread", 
            "chat_config_used", "chat_config_version_used"
        )

        # 2. Apply Trevor's Permission Logic
        user_queryset = TenantAccessFilterBackend().filter_queryset(
            self.request, queryset, self
        ).filter(user=self.request.user)
        
        admin_queryset = TenantAdminFilterBackend().filter_queryset(
            self.request, queryset, self
        )
        
        # Set union and distinct to prevent duplicates
        queryset = (user_queryset | admin_queryset).distinct()

        # 3. Handle Optional Project Filter (Query Params, NOT Headers)
        project_guid = self.request.query_params.get("project_guid")
        if project_guid:
            queryset = queryset.filter(project__guid=project_guid)

        # 4. Handle Dates
        created_at_start = self.request.query_params.get("created_at_start")
        created_at_end = self.request.query_params.get("created_at_end")
        
        if created_at_start or created_at_end:
            queryset = self._validate_dates(created_at_start, created_at_end, queryset)

        # Return the fully secured and filtered queryset to the mixin's list() method
        return queryset

    def get(self, request, *args, **kwargs):
        """
        Retrieve filtered RAG conversations based on provided parameters.
        """
        try:
            return self.list(request)
        except ValueError as e:
            return format_response_payload(
                success=False,
                message=str(e),
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            logger.error(f"Error retrieving conversations: {str(e)}")
            return format_response_payload(
                success=False,
                errors=str(e),
                message="An unexpected error occurred.",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _validate_dates(self, created_at_start, created_at_end, queryset):
        """
        Helper function to validate and apply date filters.
        MUST return the modified queryset.
        """
        if created_at_start:
            try:
                start_date = datetime.strptime(created_at_start, "%Y-%m-%d")
                queryset = queryset.filter(created_at__gte=start_date)
            except ValueError:
                raise ValueError("Invalid created_at_start format. Use YYYY-MM-DD.")
                
        if created_at_end:
            try:
                end_date = datetime.strptime(created_at_end, "%Y-%m-%d")
                queryset = queryset.filter(created_at__lte=end_date)
            except ValueError:
                raise ValueError("Invalid created_at_end format. Use YYYY-MM-DD.")
                
        return queryset

from rest_framework import status
from rest_framework.test import APITestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from datetime import datetime, timedelta
# Import your models
# from your_app.models import UserConversationHistory, Project

User = get_user_model()

class UserConversationHistoryAPIViewTests(APITestCase):
    
    def setUp(self):
        """Runs before every single test method to set up fresh data."""
        # 1. Create Users
        self.user_a = User.objects.create_user(username="user_a", password="testpass123")
        self.user_b = User.objects.create_user(username="user_b", password="testpass123")
        self.admin_user = User.objects.create_user(username="admin", password="testpass123")
        
        # Note: Set up tenant/project access for these users here 
        # based on your specific implementation (e.g., self.admin_user.is_platform_admin = True)

        # 2. Create Projects
        self.project_1 = Project.objects.create(name="Project 1", mnemonic="proj1")
        self.project_2 = Project.objects.create(name="Project 2", mnemonic="proj2")

        # 3. Create Conversations
        self.conv_user_a = UserConversationHistory.objects.create(
            user=self.user_a, project=self.project_1, preview_title="User A Query"
        )
        self.conv_user_b = UserConversationHistory.objects.create(
            user=self.user_b, project=self.project_1, preview_title="User B Query"
        )
        self.conv_admin = UserConversationHistory.objects.create(
            user=self.admin_user, project=self.project_2, preview_title="Admin Query"
        )
        
        # 4. Define the endpoint URL (Update 'conversation-list' to match your urls.py)
        # Using a dummy URL path if reverse is tricky to set up in isolation
        self.url = '/api/conversations/' # reverse('conversation-list') 

    def test_user_can_only_see_own_conversations(self):
        """Standard users should only see their own chat history."""
        self.client.force_authenticate(user=self.user_a)
        
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Adjust 'data' parsing based on your mixin's format_response_payload
        response_data = response.json()
        results = response_data if isinstance(response_data, list) else response_data.get('data', [])
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['id'], self.conv_user_a.id)

    def test_cross_tenant_data_leak_prevented(self):
        """Ensure User A cannot query User B's conversations by manipulating parameters."""
        self.client.force_authenticate(user=self.user_a)
        
        # Attempting to filter by another user's ID
        response = self.client.get(f"{self.url}?user={self.user_b.id}")
        
        results = response.json() if isinstance(response.json(), list) else response.json().get('data', [])
        
        # Should not return User B's data
        for item in results:
            self.assertNotEqual(item['id'], self.conv_user_b.id)

    def test_project_guid_filter(self):
        """Testing the optional query parameter filter for projects."""
        self.client.force_authenticate(user=self.user_a)
        
        # Filter by a project the user has data in
        response = self.client.get(f"{self.url}?project_guid={self.project_1.guid}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Filter by a project the user has NO data in (but exists)
        response_empty = self.client.get(f"{self.url}?project_guid={self.project_2.guid}")
        self.assertEqual(response_empty.status_code, status.HTTP_200_OK)
        
        results_empty = response_empty.json() if isinstance(response_empty.json(), list) else response_empty.json().get('data', [])
        self.assertEqual(len(results_empty), 0)

    def test_date_filters(self):
        """Testing the created_at_start and created_at_end filters."""
        self.client.force_authenticate(user=self.user_a)
        
        today = datetime.now().strftime("%Y-%m-%d")
        tomorrow = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")
        
        # Valid date filter
        response = self.client.get(f"{self.url}?created_at_start={today}&created_at_end={tomorrow}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Invalid date format should trigger 400 Bad Request
        response_invalid = self.client.get(f"{self.url}?created_at_start=invalid-date")
        self.assertEqual(response_invalid.status_code, status.HTTP_400_BAD_REQUEST)

    def test_union_does_not_return_duplicates(self):
        """
        Ensures that if a user is BOTH the creator of a conversation AND 
        an admin of the project, the API only returns the conversation once.
        """
        self.client.force_authenticate(user=self.admin_user)
        
        # In setup(), we already created self.conv_admin where:
        # user = self.admin_user AND project = self.project_2
        # Assuming admin_user is an admin of project_2 via TenantAdminFilterBackend...
        
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        results = response.json() if isinstance(response.json(), list) else response.json().get('data', [])
        
        # It should return exactly 1 record, not 2, proving the distinct() logic worked.
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['id'], self.conv_admin.id)

def get_base_queryset(self):
        """
        Overrides the mixin's default method to apply security and Oracle fixes,
        while maintaining the mixin's select_related optimizations.
        """
        # 1. Evaluate permissions on a raw, unoptimized queryset
        base_qs = self.model.objects.all()

        user_queryset = TenantAccessFilterBackend().filter_queryset(
            self.request, base_qs, self
        ).filter(user=self.request.user)
        
        admin_queryset = TenantAdminFilterBackend().filter_queryset(
            self.request, base_qs, self
        )
        
        # 2. Extract ONLY the IDs (The Oracle-safe distinct workaround)
        combined_qs = user_queryset | admin_queryset
        unique_ids = combined_qs.values_list('id', flat=True).distinct()

        # 3. Fetch the baseline optimized queryset from the Mixin!
        # This line automatically applies .select_related("user", "project") 
        # because of your related_fields class attribute.
        queryset = super().get_base_queryset().filter(id__in=unique_ids)

        # 4. Optional Project Filter (Query Params)
        project_guid = self.request.query_params.get("project_guid")
        if project_guid:
            queryset = queryset.filter(project__guid=project_guid)

        # 5. Handle Dates
        created_at_start = self.request.query_params.get("created_at_start")
        created_at_end = self.request.query_params.get("created_at_end")
        
        if created_at_start or created_at_end:
            queryset = self._validate_dates(created_at_start, created_at_end, queryset)

        # 6. Apply LOB defer optimization last
        return queryset.defer(
            "retrieved_documents", "metadata", "conversation_thread", 
            "chat_config_used", "chat_config_version_used"
        )

Summary
This PR addresses a critical data isolation vulnerability in the UserConversationHistoryView. Previously, non-admin users could bypass security and view chat logs from other users or tenants by manipulating request parameters. This update enforces strict row-level security by dynamically evaluating the user's tenant access and admin privileges, ensuring users only see their own conversations or conversations within projects they administer.

It also incorporates code review feedback by standardizing on query parameters instead of headers, fixes an Oracle DB limitation with DISTINCT queries, and adds comprehensive test coverage.

Key Changes

Enforced Row-Level Security: Implemented a union of TenantAccessFilterBackend (filtered by the request.user) and TenantAdminFilterBackend to safely enforce the permission matrix.

Fixed Oracle DISTINCT LOB Crash: Replaced .distinct() on the raw queryset with an id__in subquery to prevent ORA-00932 errors on LOB columns (like TextField and JSONField).

Standardized API Filtering: Moved the project filter from the Project-Guid header to a standard project_guid query parameter.

Maintained N+1 Optimizations: explicitly re-implemented .select_related() and .defer() optimizations to prevent performance regressions while bypassing super().get_base_queryset() to maintain strict control over query state.

Fixed filtering.py Typo: Corrected a critical typo in TenantAdminFilterBackend where tenant_access_mnemonics was being evaluated instead of tenant_admin_mnemonics.

Fixed Date Filtering Bug: Patched _validate_dates so it properly returns the updated queryset instead of None.

Testing Performed

Added UserConversationHistoryAPIViewTests suite.

Verified standard users can only access their own conversations (test_user_can_only_see_own_conversations).

Verified cross-tenant data leaks are actively blocked (test_cross_tenant_data_leak_prevented).

Verified tenant admins can see all conversations within their assigned projects without returning duplicates (test_union_does_not_return_duplicates).

Verified project_guid, created_at_start, and created_at_end optional filters return 200 OK and accurate datasets.