from django.db.models import Prefetch
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAdminUser

# Assuming your mixin is here
from .mixins import PaginatedAPIMixin
from .models import Message, Project, UserConversationHistory
from .serializers import AdminNegativeConversationSerializer
from .utils import format_response_payload


class AdminNegativeConversationsView(PaginatedAPIMixin, ListAPIView):
    """
    Admin-only view.
    Returns full conversation histories for any conversation that contains
    at least one message with negative feedback (liked=False).

    Security:
    - Requires User to be an Admin.
    - Requires User to have permission for the specific Project requested.
    """

    serializer_class = AdminNegativeConversationSerializer
    # Combine standard Admin check with your custom Tenant/Project permission logic
    permission_classes = [IsAdminUser, TenantAccessPermission]

    def get_queryset(self):
        """
        We don't use this standard method for the main logic because we need
        to validate the Project ID and permissions *before* we even touch the DB.

        The main logic is handled in 'list' below.
        """
        return UserConversationHistory.objects.none()

    def list(self, request, *args, **kwargs):
        project_id = request.query_params.get("project_id")

        # 1. VALIDATION: Check if ID is provided
        if not project_id:
            return format_response_payload(
                success=False,
                message="Missing required parameter.",
                errors={"project_id": "This query parameter is required."},
                status_code=400,
            )

        # 2. SECURITY: Fetch Project & Check Permissions
        # We do this FIRST. If they fail this check, we don't run the heavy conversation query.
        project = get_object_or_404(Project, guid=project_id)

        # This manually triggers your TenantAccessPermission.has_object_permission() logic
        self.check_object_permissions(request, project)

        # 3. OPTIMIZED QUERY
        # Now we know they are allowed to see this project, so we fetch the data.

        # A. Prefetch setup for the nested messages + feedback
        messages_prefetch = Prefetch(
            "messages",
            queryset=Message.objects.select_related("feedback").order_by("created_at"),
        )

        # B. Main Filter
        queryset = (
            UserConversationHistory.objects.filter(
                project=project,  # Filter by the validated project obj
                messages__feedback__liked=False,  # Filter: Has negative feedback
            )
            .distinct()
            .prefetch_related(
                messages_prefetch  # Eager load messages
            )
            .select_related("user", "project")
            .order_by("-created_at")
        )

        # 4. PAGINATION (Using your Mixin)
        # Using self.paginate_queryset from the Mixin ensures the response
        # follows your custom pagination structure.
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        # Fallback (Non-paginated)
        serializer = self.get_serializer(queryset, many=True)
        return format_response_payload(
            success=True,
            message="Negative conversations retrieved successfully.",
            data=serializer.data,
            status_code=200,
        )


from django.urls import path

from .views import AdminNegativeConversationsView

urlpatterns = [
    path(
        "admin/negative-conversations/",
        AdminNegativeConversationsView.as_view(),
        name="admin-negative-conversations",
    ),
]

from rest_framework import serializers

from .models import Message, UserConversationHistory, UserFeedback


class AdminFeedbackSerializer(serializers.ModelSerializer):
    """
    Shows feedback details attached to a message.
    """

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
    """
    Shows a single message turn with its feedback and metadata.
    """

    feedback = AdminFeedbackSerializer(read_only=True)

    class Meta:
        model = Message
        fields = [
            "id",
            "message_role",
            "text",
            "metadata",  # Often contains per-turn token usage/chunks
            "created_at",
            "feedback",
        ]


class AdminNegativeConversationSerializer(serializers.ModelSerializer):
    """
    Shows the Conversation metadata, retrieved docs, and the full transcript.
    """

    # 1. Nested Serializer: Loads all messages for this conversation
    messages = AdminMessageSerializer(many=True, read_only=True)

    # Flatten user details for easier reading in the admin table
    user_email = serializers.CharField(source="user.email", read_only=True)
    project_name = serializers.CharField(source="project.name", read_only=True)

    class Meta:
        model = UserConversationHistory
        fields = [
            "id",
            "preview_title",
            "user_email",
            "project_name",
            "retrieved_documents",  # Critical for debugging RAG context
            "metadata",  # System config/global stats
            "created_at",
            "messages",  # The full transcript
        ]
