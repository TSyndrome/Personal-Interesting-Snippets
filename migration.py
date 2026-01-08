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
