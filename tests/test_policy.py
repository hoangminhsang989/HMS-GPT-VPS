from hms_gpt_vps.policy import Decision, PolicyRequest, evaluate


def test_missing_capability_denied() -> None:
    assert evaluate(PolicyRequest(capability="", project_id="p1")) is Decision.DENY


def test_missing_project_denied() -> None:
    assert evaluate(PolicyRequest(capability="git.status")) is Decision.DENY


def test_destructive_action_requires_approval() -> None:
    request = PolicyRequest(capability="file.delete", project_id="p1", destructive=True)
    assert evaluate(request) is Decision.REQUIRE_APPROVAL


def test_destructive_action_with_approval_allowed() -> None:
    request = PolicyRequest(
        capability="file.delete",
        project_id="p1",
        destructive=True,
        explicitly_approved=True,
    )
    assert evaluate(request) is Decision.ALLOW


def test_scoped_non_destructive_action_allowed() -> None:
    request = PolicyRequest(capability="git.status", project_id="p1")
    assert evaluate(request) is Decision.ALLOW
