import difflib

from django.db import migrations


def link_feedback_fuzzy(apps, schema_editor):
    UserFeedback = apps.get_model("insights", "UserFeedback")
    Message = apps.get_model("insights", "Message")

    # Optimization: Prefetch or iterator isn't helpful here because we write individually.
    # We just filter for rows that actually have data to work with.
    feedbacks = UserFeedback.objects.filter(
        response_text__isnull=False, user_conversation_history__isnull=False
    ).exclude(response_text="")

    linked_count = 0
    THRESHOLD = 0.90  # 90% Match Required

    for feedback in feedbacks:
        # Fetch only the messages in the relevant conversation (The "Pool")
        candidates = Message.objects.filter(
            user_conversation_history_id=feedback.user_conversation_history_id
        ).order_by("-created_at")  # Deterministic: prefer newest if duplicate

        fb_text = feedback.response_text.strip()
        best_match = None
        best_score = 0.0

        for msg in candidates:
            msg_text = (msg.text or "").strip()

            # Fast Check: Exact match (avoids difflib overhead)
            if msg_text == fb_text:
                best_match = msg
                best_score = 1.0
                break  # Cannot beat 100%

            # Slow Check: Fuzzy match
            score = difflib.SequenceMatcher(None, fb_text, msg_text).ratio()

            if score > best_score:
                best_score = score
                best_match = msg

        # Apply Link
        if best_match and best_score >= THRESHOLD:
            # Check if this exact link already exists to avoid redundant writes
            if best_match.feedback_id != feedback.id:
                best_match.feedback = feedback
                best_match.save(update_fields=["feedback"])
                linked_count += 1

    print(f"\nMigration successfully linked {linked_count} feedback entries.")


def reverse_func(apps, schema_editor):
    Message = apps.get_model("insights", "Message")
    Message.objects.update(feedback=None)


class Migration(migrations.Migration):
    dependencies = [
        ("insights", "0002_alter_userfeedback_feedback_category"),
    ]

    operations = [
        migrations.RunPython(link_feedback_fuzzy, reverse_func),
        migrations.RemoveField(model_name="userfeedback", name="query_text"),
        migrations.RemoveField(model_name="userfeedback", name="response_text"),
    ]
