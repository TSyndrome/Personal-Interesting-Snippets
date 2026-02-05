# alerts/models.py

import uuid
import logging
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db.models import Q

logger = logging.getLogger(__name__)


class TenantAnnouncement(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    project = models.ForeignKey(
        "Project",
        on_delete=models.CASCADE,
        related_name="tenant_announcements",
    )

    title = models.CharField(max_length=200)
    message = models.TextField()

    is_active = models.BooleanField(default=True)

    starts_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["project"],
                condition=Q(is_active=True),
                name="one_active_tenant_announcement",
            )
        ]

    def clean(self):
        if self.is_active:
            existing = TenantAnnouncement.objects.filter(
                project=self.project,
                is_active=True,
            ).exclude(id=self.id)

            if existing.exists():
                raise ValidationError(
                    "This project already has an active announcement."
                )

        if self.expires_at and self.expires_at <= self.starts_at:
            raise ValidationError("expires_at must be after starts_at")

    def save(self, *args, **kwargs):
        logger.info("Saving TenantAnnouncement %s", self.id)
        self.full_clean()
        super().save(*args, **kwargs)

    def is_current(self):
        now = timezone.now()

        return (
            self.is_active
            and self.starts_at <= now
            and (not self.expires_at or self.expires_at > now)
        )

    def __str__(self):
        return f"{self.project.name}: {self.title}"

# alerts/serializers.py

from rest_framework import serializers
from .models import TenantAnnouncement


class TenantAnnouncementSerializer(serializers.ModelSerializer):

    class Meta:
        model = TenantAnnouncement
        fields = "__all__"
        read_only_fields = ("id", "created_at", "updated_at", "created_by")

    def validate(self, attrs):
        project = attrs.get("project")
        is_active = attrs.get("is_active", True)

        if project and is_active:
            qs = TenantAnnouncement.objects.filter(
                project=project,
                is_active=True,
            )

            if self.instance:
                qs = qs.exclude(id=self.instance.id)

            if qs.exists():
                raise serializers.ValidationError(
                    "Only one active announcement allowed per project."
                )

        return attrs

# alerts/views.py

import logging
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated

from .models import TenantAnnouncement
from .serializers import TenantAnnouncementSerializer
from common.responses import format_response_payload

logger = logging.getLogger(__name__)


class TenantAnnouncementViewSet(viewsets.ModelViewSet):
    serializer_class = TenantAnnouncementSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return TenantAnnouncement.objects.select_related("project")

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save(created_by=request.user)

            logger.info("TenantAnnouncement created by %s", request.user.id)

            return format_response_payload(
                success=True,
                data=serializer.data,
                message="Announcement created",
                status_code=status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.exception("Create TenantAnnouncement failed")
            return format_response_payload(
                success=False,
                message="Failed to create announcement",
                errors=str(e),
                status_code=status.HTTP_400_BAD_REQUEST,
            )

    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            logger.info("TenantAnnouncement updated %s", instance.id)

            return format_response_payload(
                success=True,
                data=serializer.data,
                message="Announcement updated",
            )

        except Exception as e:
            logger.exception("Update TenantAnnouncement failed")
            return format_response_payload(
                success=False,
                message="Failed to update announcement",
                errors=str(e),
                status_code=status.HTTP_400_BAD_REQUEST,
            )

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            instance.delete()

            logger.info("TenantAnnouncement deleted %s", instance.id)

            return format_response_payload(
                success=True,
                message="Announcement deleted",
            )

        except Exception as e:
            logger.exception("Delete TenantAnnouncement failed")
            return format_response_payload(
                success=False,
                message="Failed to delete announcement",
                errors=str(e),
                status_code=status.HTTP_400_BAD_REQUEST,
            )

    @action(detail=False, methods=["get"], url_path="active/(?P<project_id>[^/.]+)")
    def active(self, request, project_id=None):
        """
        Returns single active announcement for project.
        """

        try:
            now = timezone.now()

            announcement = (
                TenantAnnouncement.objects.filter(
                    project_id=project_id,
                    is_active=True,
                    starts_at__lte=now,
                )
                .exclude(expires_at__lte=now)
                .first()
            )

            if not announcement:
                return format_response_payload(
                    success=True,
                    data=None,
                    message="No active announcement",
                )

            serializer = self.get_serializer(announcement)

            return format_response_payload(
                success=True,
                data=serializer.data,
            )

        except Exception as e:
            logger.exception("Fetch active TenantAnnouncement failed")

            return format_response_payload(
                success=False,
                message="Unable to fetch announcement",
                errors=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        
router.register(r"tenant-announcements", TenantAnnouncementViewSet)

Title: Add Tenant Announcements API for Project-Level Chat Alerts

Description

As a platform administrator, I want to configure time-bound announcements per tenant (project) so end users see important alert banners in the chat experience until expiry.

This feature introduces a TenantAnnouncement model with DRF endpoints allowing admins to create, update, delete, activate/deactivate, and retrieve announcements. Only one active announcement is allowed per project at any time. Announcements respect start and expiration timestamps using timezone-aware datetime handling.

The frontend consumes a single endpoint to fetch the currently active announcement for a project and displays it until expiration.

All API responses follow the standardized format_response_payload structure, with logging and defensive error handling throughout.

Pull Request Title

Add Tenant Announcements API for Project-Level Chat Alerts

📝 Pull Request Description
Summary

Introduces tenant-level announcements for chat alert banners, allowing admins to configure time-bound messages per project.

Key highlights:

New TenantAnnouncement model with DB-level constraint enforcing one active announcement per project

Full CRUD via DRF

Active announcement endpoint for frontend consumption

Timezone-aware start/expiry handling

Integrated standardized API responses via format_response_payload

Logging and defensive error handling throughout

This enables product and ops teams to broadcast important messages to all users within a tenant until expiration.

Changes Included

Added TenantAnnouncement model with validation and constraints

DRF serializer and viewset

/active/{project_id} endpoint

Integrated standardized response payloads

Logging for create/update/delete/fetch flows

Router registration