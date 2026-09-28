"""
End-to-end GraphQL active-injection testing through the real pipeline:
introspection -> `core.graphql_schema.parse_introspection` -> merged into the
same `injection_surface` REST/HTML discovery populates -> hypothesis ->
capability request -> Gateway (scope+budget) -> controlled probe (GraphQL
`{"query", "variables"}` JSON envelope) -> observation -> independent
validation -> coverage -> report. Against local, deliberately (and safely)
vulnerable/degraded GraphQL fixtures (see `tests/conftest.py`).
"""

from __future__ import annotations

from core.budget import BudgetLimits
from core.models import FindingStatus

FAST = dict(authorized=True, learn_lessons=False)
GENEROUS = BudgetLimits(max_tool_calls=200, max_iterations=120, max_expensive_ops=30, max_llm_calls=50)


def _by_category(state, category):
    return [f for f in state.findings if f.category == category]


def _confirmed(findings):
    return [f for f in findings if f.status == FindingStatus.CONFIRMED]


def _graphql_params(state):
    surface = state.profile.attributes.get("injection_surface", {})
    return surface.get("/graphql", {}).get("params", [])


# -- discovery: correct fields/args, correct evidence, scalars only -----------------

async def test_graphql_query_scalar_argument_is_discovered_with_spec_evidence(graphql_server):
    from core.assessment import run_assessment
    state = await run_assessment(graphql_server.url, max_risk="moderate", limits=GENEROUS, **FAST)
    params = {p["name"]: p for p in _graphql_params(state)}
    assert "userById.id" in params
    p = params["userById.id"]
    assert p["location"] == "graphql" and p["evidence"] == "spec"
    assert p["operation_type"] == "query" and p["field"] == "userById"
    assert p["variable_path"] == "id" and p["variable_type"] == "ID!"
    assert p["top_level_args"] == {"id": "ID!"}
    assert p["baseline_variables"] == {"id": "1"}


async def test_graphql_list_argument_is_never_discovered_as_a_testable_parameter(graphql_server):
    from core.assessment import run_assessment
    state = await run_assessment(graphql_server.url, max_risk="moderate", limits=GENEROUS, **FAST)
    names = {p["name"] for p in _graphql_params(state)}
    assert not any("tags" in n for n in names)          # the LIST argument on userById
    assert "userById.id" in names                        # its scalar sibling is still testable


async def test_graphql_mutation_arguments_are_discovered_but_never_added_to_active_testing(graphql_server):
    from core.assessment import run_assessment
    state = await run_assessment(graphql_server.url, max_risk="moderate", limits=GENEROUS, **FAST)
    # Introspection parsing itself must find all three nested scalar leaves...
    ops = {op["field"]: op for op in state.profile.attributes.get("graphql_operations", [])}
    assert "createUser" in ops
    mutation_leaves = {leaf["variable_path"] for leaf in ops["createUser"]["testable_leaves"]}
    assert mutation_leaves == {"input.name", "input.age", "input.active"}
    # ...but mutation-argument testing is a deliberate, documented gap: none of
    # those leaves may reach `injection_surface` (which drives active testing).
    names = {p["name"] for p in _graphql_params(state)}
    assert not any(n.startswith("createUser.") for n in names)
    assert not any(h.endpoint == "/graphql" and "createUser" in h.parameter for h in state.injection_hypotheses)


async def test_graphql_arguments_are_never_proposed_for_xss(graphql_server):
    from core.assessment import run_assessment
    state = await run_assessment(graphql_server.url, max_risk="moderate", limits=GENEROUS, **FAST)
    assert not any(h.type.value == "xss" and h.location == "graphql" for h in state.injection_hypotheses)
    assert not _by_category(state, "CrossSiteScripting")


async def test_graphql_url_like_argument_gets_an_ssrf_hypothesis(graphql_server):
    from core.assessment import run_assessment
    state = await run_assessment(graphql_server.url, max_risk="moderate", limits=GENEROUS, **FAST)
    assert any(h.type.value == "ssrf" and h.location == "graphql" and h.parameter == "webhookUrl"
              for h in state.injection_hypotheses)


# -- end-to-end confirmation: a real GraphQL SQLi signal reaches CONFIRMED ----------

async def test_graphql_sql_injection_is_discovered_probed_and_confirmed_end_to_end(graphql_server):
    from core.assessment import run_assessment
    state = await run_assessment(graphql_server.url, max_risk="moderate", limits=GENEROUS, **FAST)
    sqli = _by_category(state, "SQLInjection")
    confirmed = _confirmed(sqli)
    graphql_confirmed = [f for f in confirmed if f.signal.get("location") == "graphql"]
    assert graphql_confirmed and graphql_confirmed[0].validator == "sql_injection"
    assert graphql_confirmed[0].signal.get("field") == "userById"
    assert any(h.type.value == "sql_injection" and h.location == "graphql" and h.finding_id
              for h in state.injection_hypotheses)


async def test_graphql_non_vulnerable_field_produces_no_false_positive(graphql_server):
    from core.assessment import run_assessment
    state = await run_assessment(graphql_server.url, max_risk="moderate", limits=GENEROUS, **FAST)
    sqli = _by_category(state, "SQLInjection")
    # safeById never varies its response with input: it must never appear as a
    # SQLInjection candidate/finding, confirmed or otherwise.
    assert not any(f.signal.get("field") == "safeById" for f in sqli)
    safe_hyps = [h for h in state.injection_hypotheses
                if h.type.value == "sql_injection" and h.location == "graphql" and h.parameter == "id"
                and h.endpoint == "/graphql"]
    # (userById.id and safeById.id share the same bare "id" variable_path --
    # distinguish by whether a candidate/finding was actually raised for it.)
    assert any(not h.finding_id for h in safe_hyps) or len(safe_hyps) <= 1


# -- introspection disabled: honest limitation, no fabricated surface --------------

async def test_graphql_introspection_disabled_records_a_limitation_and_no_surface(
        graphql_no_introspection_server):
    from core.assessment import run_assessment
    state = await run_assessment(graphql_no_introspection_server.url, max_risk="moderate",
                                 limits=GENEROUS, **FAST)
    assert state.phase == "complete"                      # never crashes
    assert _graphql_params(state) == []
    assert "graphql_operations" not in state.profile.attributes
    assert any("introspection" in l.lower() for l in state.limitations)
    assert not _by_category(state, "GraphQLIntrospectionEnabled")
    assert not _by_category(state, "SQLInjection")


# -- malformed/incomplete introspection: graceful degradation, no crash ------------

async def test_graphql_malformed_introspection_degrades_without_crashing_or_fabricating(
        graphql_malformed_server):
    from core.assessment import run_assessment
    state = await run_assessment(graphql_malformed_server.url, max_risk="moderate", limits=GENEROUS, **FAST)
    assert state.phase == "complete"                      # never crashes
    # The cheap passive check still saw '__schema', so the low-severity
    # "introspection enabled" observation is honestly still raised...
    assert _by_category(state, "GraphQLIntrospectionEnabled")
    # ...but the full schema was unusable (no 'types'), so nothing was fabricated.
    assert state.profile.attributes.get("graphql_operations") == []
    assert _graphql_params(state) == []
    assert not _by_category(state, "SQLInjection")
    assert any("introspection" in l.lower() or "schema" in l.lower() for l in state.limitations)


# -- scope enforcement applies identically to GraphQL parameters -------------------

async def test_graphql_active_testing_is_blocked_by_default_scope(graphql_server):
    from core.assessment import run_assessment
    state = await run_assessment(graphql_server.url, limits=GENEROUS, **FAST)   # default low risk
    assert not _by_category(state, "SQLInjection")
    assert not any(h.location == "graphql" for h in state.injection_hypotheses)
    assert all(c.status != "out_of_scope" for c in state.tool_calls)
