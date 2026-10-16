from soc_bot.rbac import AccessPolicy, Permission

POLICY = AccessPolicy(
    read_role_ids=frozenset({1}),
    triage_role_ids=frozenset({2}),
    response_role_ids=frozenset({3}),
    allowed_channel_ids=frozenset({100}),
)


def test_no_roles_denied():
    assert POLICY.level_for([999]) is None
    assert not POLICY.is_allowed([999], Permission.READ)


def test_tiers_are_hierarchical():
    assert POLICY.is_allowed([3], Permission.READ)
    assert POLICY.is_allowed([3], Permission.TRIAGE)
    assert POLICY.is_allowed([2], Permission.READ)
    assert not POLICY.is_allowed([2], Permission.RESPONSE)
    assert not POLICY.is_allowed([1], Permission.TRIAGE)


def test_highest_role_wins():
    assert POLICY.level_for([1, 3]) is Permission.RESPONSE


def test_channel_allowlist():
    assert POLICY.channel_allowed(100)
    assert not POLICY.channel_allowed(200)
    assert not POLICY.channel_allowed(None)


def test_empty_channel_list_allows_nothing():
    policy = AccessPolicy(frozenset({1}), frozenset(), frozenset())
    assert not policy.channel_allowed(200)
