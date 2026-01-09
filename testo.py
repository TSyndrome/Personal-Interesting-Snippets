class UserFeedbackExportSerializer(serializers.ModelSerializer):
    tenant = serializers.CharField(source="project.name", read_only=True, default="")
    user = UserMinimalSerializer(read_only=True)
    timestamp = serializers.SerializerMethodField()

    user_conversation_history = serializers.SerializerMethodField()
    user_conversation_log = serializers.SerializerMethodField()

    assistant_message_with_feedback = serializers.SerializerMethodField()
    previous_user_message = serializers.SerializerMethodField()

    class Meta:
        model = UserFeedback
        fields = [
            "id",
            "tenant",
            "user",
            "assistant_message_with_feedback",
            "previous_user_message",
            "user_conversation_history",
            "user_conversation_log",
            "feedback_category",
            "free_text_feedback",
            "liked",
            "timestamp",
        ]


def _get_feedback_message(self, obj):
    try:
        return Message.objects.select_related("user_conv_history").get(
            feedback=obj,
            message_role="assistant",
        )
    except Message.DoesNotExist:
        return None


def get_assistant_message_with_feedback(self, obj):
    message = self._get_feedback_message(obj)
    return message.text if message else "No assistant message found"


def get_previous_user_message(self, obj):
    message = self._get_feedback_message(obj)
    if not message:
        return "No previous user message found"

    previous_user_message = (
        Message.objects.filter(
            user_conv_history=message.user_conv_history,
            message_role="user",
            created_at__lt=message.created_at,
        )
        .order_by("-created_at")
        .first()
    )

    return (
        previous_user_message.text
        if previous_user_message
        else "No previous user message found"
    )


# queryset = UserFeedback.objects.select_related(
#     "project",
#     "user",
# ).prefetch_related(
#     "message_set",
# )
