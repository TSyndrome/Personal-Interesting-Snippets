import difflib

from django.db import migrations


def link_feedback_optimized(apps, schema_editor):
    """
    Links UserFeedback to Messages using fuzzy matching logic.
    Optimized with prefetch_related to avoid N+1 query problems.
    """
    UserFeedback = apps.get_model("insights", "UserFeedback")
    Message = apps.get_model("inference", "Message")

    # 1. OPTIMIZED QUERYSET
    # We fetch Feedbacks, JOIN the Conversation History,
    # and PREFETCH all Messages belonging to that History in one go.
    feedbacks = (
        UserFeedback.objects.filter(
            response_text__isnull=False, user_conversation_history__isnull=False
        )
        .exclude(response_text="")
        .select_related("user_conversation_history")
        .prefetch_related("user_conversation_history__messages")
    )

    linked_count = 0
    THRESHOLD = 0.90  # 90% Similarity required

    for feedback in feedbacks:
        # 2. IN-MEMORY LOOKUP (Zero DB hits here)
        # Accessing .messages.all() here hits the pre-fetched cache.
        # The ordering ("-created_at") is automatic due to Message model Meta.
        candidates = feedback.user_conversation_history.messages.all()

        fb_text = feedback.response_text.strip()
        best_match = None
        best_score = 0.0

        for msg in candidates:
            msg_text = (msg.text or "").strip()

            # A. FAST TRACK: Exact Match
            if msg_text == fb_text:
                best_match = msg
                best_score = 1.0
                break  # Cannot beat 100%, stop looking.

            # B. SLOW TRACK: Fuzzy Match
            # Only run if we haven't found an exact match yet
            score = difflib.SequenceMatcher(None, fb_text, msg_text).ratio()

            if score > best_score:
                best_score = score
                best_match = msg

        # 3. SAVE THE LINK
        if best_match and best_score >= THRESHOLD:
            # Idempotency check: Don't overwrite if already linked correctly
            if best_match.feedback_id != feedback.id:
                best_match.feedback = feedback
                best_match.save(update_fields=["feedback"])
                linked_count += 1

    print(f"\nMigration Complete: Linked {linked_count} feedback entries to messages.")


def reverse_func(apps, schema_editor):
    """
    Reverses the linking (sets FK to Null).
    Note: Cannot restore the dropped text columns if this is reversed.
    """
    Message = apps.get_model("inference", "Message")
    Message.objects.update(feedback=None)


class Migration(migrations.Migration):
    dependencies = [
        # Ensure this matches your actual last migration file
        ("insights", "0002_alter_userfeedback_feedback_category"),
    ]

    operations = [
        # STEP 1: Link the data (Must happen while columns still exist)
        migrations.RunPython(link_feedback_optimized, reverse_func),
        # STEP 2: Remove the legacy text fields
        migrations.RemoveField(
            model_name="userfeedback",
            name="query_text",
        ),
        migrations.RemoveField(
            model_name="userfeedback",
            name="response_text",
        ),
    ]


from rest_framework import serializers

from .models import Message, User, UserConversationHistory, UserFeedback


# --- REUSED MINIMAL SERIALIZER ---
class UserMinimalSerializer(serializers.ModelSerializer):
    display_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["username", "first_name", "last_name", "display_name"]

    def get_display_name(self, obj):
        first = (obj.first_name or "").strip()
        last = (obj.last_name or "").strip()
        return f"{last}, {first}".strip(", ") if (first or last) else obj.username


# --- ADMIN VIEW SERIALIZERS ---


class AdminFeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserFeedback
        fields = [
            "id",
            "liked",
            "feedback_category",
            "free_text_feedback",
            "created_at",
        ]


class AdminMessageSerializer(serializers.ModelSerializer):
    feedback = AdminFeedbackSerializer(read_only=True)

    class Meta:
        model = Message
        fields = ["id", "message_role", "text", "metadata", "created_at", "feedback"]


class AdminNegativeConversationSerializer(serializers.ModelSerializer):
    # Reuse the minimal user serializer for cleaner nested data
    user = UserMinimalSerializer(read_only=True)

    # Nested transcript
    messages = AdminMessageSerializer(many=True, read_only=True)

    project_name = serializers.CharField(source="project.name", read_only=True)

    class Meta:
        model = UserConversationHistory
        fields = [
            "id",
            "preview_title",
            "preview_content",  #
            "user",  # Reused Serializer
            "project_name",
            "retrieved_documents",  #
            "metadata",  #
            "conversation_thread",  # Full JSON thread if stored here
            "created_at",
            "messages",  # The computed message list from the view
        ]


from django.db.models import Prefetch
from django.shortcuts import get_object_or_404

# 1. Import extend_schema_view
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiTypes,
    extend_schema,
    extend_schema_view,
)
from rest_framework import status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAdminUser

from .mixins import PaginatedAPIMixin
from .models import Message, Project, UserConversationHistory
from .serializers import AdminNegativeConversationSerializer
from .utils import format_response_payload


# 2. Decorate the CLASS, targeting the 'get' method
@extend_schema_view(
    get=extend_schema(
        summary="List Negative Feedback Conversations",
        description="Retrieves full conversation transcripts for any session containing negative feedback. Restricted to Admins.",
        parameters=[
            OpenApiParameter(
                name="project_id",
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.QUERY,
                description="The GUID of the project to filter by.",
                required=True,
            ),
        ],
        responses={
            200: AdminNegativeConversationSerializer(many=True),
            400: "Missing project_id",
            403: "Permission Denied",
            404: "Project Not Found",
        },
    )
)
class AdminNegativeConversationsView(PaginatedAPIMixin, ListAPIView):
    """
    Admin-only view.
    Returns full conversation histories for any conversation that contains
    at least one message with negative feedback (liked=False).
    """

    serializer_class = AdminNegativeConversationSerializer
    permission_classes = [IsAdminUser, TenantAccessPermission]

    def get_queryset(self):
        return UserConversationHistory.objects.none()

    # 3. Remove @extend_schema from here (it's now handled by the class decorator)
    def list(self, request, *args, **kwargs):
        project_id = request.query_params.get("project_id")

        if not project_id:
            return format_response_payload(
                success=False,
                message="Missing required parameter.",
                errors={"project_id": "This query parameter is required."},
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        try:
            project = get_object_or_404(Project, guid=project_id)
            self.check_object_permissions(request, project)

            messages_prefetch = Prefetch(
                "messages",
                queryset=Message.objects.select_related("feedback").order_by(
                    "created_at"
                ),
            )

            queryset = (
                UserConversationHistory.objects.filter(
                    project=project, messages__feedback__liked=False
                )
                .distinct()
                .prefetch_related(messages_prefetch)
                .select_related("user", "project")
                .order_by("-created_at")
            )

            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(queryset, many=True)
            return format_response_payload(
                success=True,
                message="Negative conversations retrieved successfully.",
                data=serializer.data,
                status_code=status.HTTP_200_OK,
            )

        except PermissionDenied:
            return format_response_payload(
                success=False,
                message="You do not have permission to view this project.",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        except Exception as e:
            return format_response_payload(
                success=False,
                message="An unexpected error occurred.",
                errors=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
