import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

# Import your actual models.
# Adjust the import path 'insights.models' to your actual app name.
from insights.models import Message, Project, UserConversationHistory, UserFeedback
from rest_framework import status
from rest_framework.test import APIClient

User = get_user_model()


class AdminNegativeConversationListViewTests(TestCase):
    def setUp(self):
        """
        Setup runs before every test.
        We create a User, a Project, and some dummy conversation data.
        """
        self.client = APIClient()

        # 1. Create a User and Auth Headers
        self.user = User.objects.create_user(
            username="admin_test", password="password123", email="admin@example.com"
        )
        self.client.force_authenticate(user=self.user)

        # 2. Create a Project
        # Assuming your TenantAccessPermission checks logic based on this.
        # You might need to link this project to the user's tenant if your models require it.
        self.project = Project.objects.create(
            name="Test Project",
            guid=uuid.uuid4(),
            # tenant=self.user.tenant  <-- Add this if your Permission class requires it
        )

        # 3. Create a secondary project (to test isolation)
        self.other_project = Project.objects.create(
            name="Other Project", guid=uuid.uuid4()
        )

        # URL for the view (Use the actual name defined in your urls.py)
        # Assuming path name is 'admin-negative-conversations-list'
        # If using a raw string URL, verify it matches your urls.py
        self.url = "/api/v1/admin/negative-conversations/list/"

    def create_conversation_with_feedback(
        self, project, is_negative=True, message_text="Test"
    ):
        """Helper to create a full chain: History -> Message -> Feedback"""

        # A. Conversation History
        history = UserConversationHistory.objects.create(
            project=project,
            user=self.user,
            preview_title=f"Chat about {message_text}",
            preview_content="Preview...",
            uuid=uuid.uuid4(),
        )

        # B. Message
        message = Message.objects.create(
            user_conversation_history=history,
            message_role="assistant",
            text=message_text,
        )

        # C. Feedback
        UserFeedback.objects.create(
            user=self.user,
            project=project,
            user_conversation_history=history,
            # Link feedback to the message (assuming your model has this reverse relation setup)
            # Based on your migration script, Message has 'feedback' FK
        )

        # Manually linking the feedback to the message for the test
        feedback = UserFeedback.objects.last()
        feedback.liked = not is_negative  # False if negative, True if positive
        feedback.save()

        message.feedback = feedback
        message.save()

        return history

    def test_authentication_required(self):
        """Test that unauthenticated users get 401/403."""
        self.client.logout()
        response = self.client.get(self.url, {"project_id": self.project.guid})
        self.assertIn(
            response.status_code,
            [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN],
        )

    def test_missing_project_id_param(self):
        """Test that missing project_id returns 400."""
        response = self.client.get(self.url)  # No params

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data["success"])
        self.assertIn("project_id", str(response.data))

    def test_invalid_project_id_format(self):
        """Test that a non-UUID project_id returns 404 (or 400 depending on validation)."""
        response = self.client.get(self.url, {"project_id": "not-a-uuid"})
        # Django usually returns 404 if get_object_or_404 fails on GUID lookup
        # or 400 if validation fails before that.
        self.assertNotEqual(response.status_code, status.HTTP_200_OK)

    def test_filter_only_negative_conversations(self):
        """
        CRITICAL: Ensure the view ONLY returns conversations with negative feedback.
        """
        # 1. Create a NEGATIVE conversation (Should appear)
        neg_conv = self.create_conversation_with_feedback(
            self.project, is_negative=True
        )

        # 2. Create a POSITIVE conversation (Should be hidden)
        self.create_conversation_with_feedback(self.project, is_negative=False)

        # 3. Create a NEGATIVE conversation in ANOTHER project (Should be hidden)
        self.create_conversation_with_feedback(self.other_project, is_negative=True)

        # Call API
        response = self.client.get(self.url, {"project_id": self.project.guid})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data[
            "data"
        ]  # Accessing the 'data' key from your format_response_payload

        # Assertions
        self.assertEqual(len(data), 1)  # Only 1 valid conversation
        self.assertEqual(
            data[0]["id"], str(neg_conv.uuid)
        )  # Ensure it's the correct one

    def test_distinct_results(self):
        """
        CRITICAL: If a conversation has 2 negative messages, it should appear ONLY ONCE.
        """
        # 1. Create conversation
        history = UserConversationHistory.objects.create(
            project=self.project, user=self.user, uuid=uuid.uuid4()
        )

        # 2. Add TWO negative messages to the same conversation
        for i in range(2):
            msg = Message.objects.create(
                user_conversation_history=history, text=f"Bad {i}"
            )
            fb = UserFeedback.objects.create(
                liked=False, project=self.project, user=self.user
            )
            msg.feedback = fb
            msg.save()

        # Call API
        response = self.client.get(self.url, {"project_id": self.project.guid})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]

        self.assertEqual(len(data), 1)  # Should still be length 1, not 2
        self.assertEqual(data[0]["id"], str(history.uuid))

    def test_response_structure_is_card(self):
        """Ensure the serializer returns the lightweight 'Card' structure."""
        self.create_conversation_with_feedback(self.project, is_negative=True)

        response = self.client.get(self.url, {"project_id": self.project.guid})
        item = response.data["data"][0]

        # Check fields present in AdminConversationCardSerializer
        self.assertIn("id", item)
        self.assertIn("preview_title", item)
        self.assertIn("created_at", item)
        self.assertIn("user", item)
        self.assertIn("project_name", item)

        # Check fields ABSENT (Rich fields should NOT be here)
        self.assertNotIn("messages", item)
        self.assertNotIn("retrieved_documents", item)
        self.assertNotIn("conversation_thread", item)
