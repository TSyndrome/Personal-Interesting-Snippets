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


from django.shortcuts import get_object_or_404
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiTypes,
    extend_schema,
    extend_schema_view,
)
from rest_framework import status
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAdminUser, IsAuthenticated

from .mixins import PaginatedAPIMixin
from .models import Project, UserConversationHistory
from .permissions import TenantAccessPermission
from .serializers import AdminConversationCardSerializer
from .utils import format_response_payload


@extend_schema_view(
    get=extend_schema(
        summary="List Negative Conversation Cards",
        description="Returns a lightweight list of all conversations in the project containing negative feedback.",
        parameters=[
            OpenApiParameter(
                name="project_id",
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.QUERY,
                required=True,
            ),
        ],
        responses={200: AdminConversationCardSerializer(many=True)},
    )
)
class AdminNegativeConversationListView(PaginatedAPIMixin, GenericAPIView):
    """
    Paginated List View for Admin Dashboard.
    Filters: Project + Has Negative Feedback.
    Output: Minimal 'Card' data.
    """

    serializer_class = AdminConversationCardSerializer
    # Adjust permissions as needed (e.g., IsAdminUser)
    permission_classes = [IsAuthenticated, TenantAccessPermission]

    def get_base_queryset(self):
        # 1. VALIDATION
        project_id = self.request.query_params.get("project_id")
        if not project_id:
            raise ValidationError({"project_id": "Required."})

        # 2. FETCH PROJECT
        # get_object_or_404 automatically handles the 404 response
        project = get_object_or_404(Project, guid=project_id)

        # 3. PERMISSION CHECK
        # Ensures the requestor has access to this Tenant/Project
        self.check_object_permissions(self.request, project)

        # 4. OPTIMIZED QUERY
        # Logic:
        # - Filter by Project
        # - Filter where ANY message has liked=False
        # - distinct() prevents duplicates if a chat has 5 negative messages
        # - select_related() fetches User + Project in the same SQL query
        return (
            UserConversationHistory.objects.filter(
                project=project, messages__feedback__liked=False
            )
            .distinct()
            .select_related("user", "project")
            .order_by("-created_at")
        )

    def get(self, request, *args, **kwargs):
        """
        API Entry Point.
        """
        try:
            # Calls get_base_queryset() -> filters -> paginates
            return self.list(request, *args, **kwargs)

        except (ValidationError, NotFound) as e:
            status_code = (
                status.HTTP_404_NOT_FOUND
                if isinstance(e, NotFound)
                else status.HTTP_400_BAD_REQUEST
            )
            return format_response_payload(
                success=False,
                message=str(e.detail) if hasattr(e, "detail") else str(e),
                status_code=status_code,
            )
        except Exception as e:
            return format_response_payload(
                success=False,
                message="An unexpected error occurred.",
                errors=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
