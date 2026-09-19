"""Planner, adaptive re-planning, LLM boundaries, agent contract."""

import pytest

from agents.base import Agent, AgentResult
from agents.registry import AgentRegistry
from core.assessment import run_assessment
from core.budget import BudgetLimits, BudgetManager
from core.models import FindingStatus, Severity
from core.scope import Scope, ScopeValidator
from core.state import AssessmentState
from intelligence.context import ContextManager
from intelligence.llm import LLM, extract_json
from intelligence.planner import Planner
from intelligence.rag import KnowledgeBase
from raven_mcp.gateway import Gateway
from raven_mcp.models import ToolDefinition
from raven_mcp.registry import ToolRegistry


class ScoutAgent(Agent):
    """Discovers a new surface: this is the 'new discovery' that must change the plan."""
    name, capabilities = "scout", ["scan"]

    def applies(self, p):  # always relevant
        return True

    def propose_tasks(self, state):
        return [self.task("scout", "scan", "Network services", "Scout the target", priority=90)]

    async def run(self, task, ctx):
        await ctx.call("scan", {})
        ctx.profile.add_surface("tcp:9999")            # new knowledge
        ctx.profile.add_service({"port": 9999, "protocol": None})
        return AgentResult(summary="found port 9999")


class FollowupAgent(Agent):
    """Only has work once a service exists: a *different capability* than the scout's."""
    name, capabilities = "followup", ["deep_probe"]

    def applies(self, p):
        return bool(p.services)

    def propose_tasks(self, state):
        return [self.task(f"probe::{s['port']}", "deep_probe", "Network services",
                          f"Probe port {s['port']}", priority=70, port=s["port"]) for s in state.profile.services]

    async def run(self, task, ctx):
        res = await ctx.call("deep_probe", {"port": task.params["port"]})
        ctx.candidate(title="Discovered thing", category="X", severity=Severity.LOW, surface="Network services",
                      location="here", description="d", signal={"validator": "made-up", "port": task.params["port"]})
        return AgentResult(success=res.ok, summary=str(res.data))


def _registry(*agents):
    r = AgentRegistry()
    for a in agents:
        r.register(a)
    return r


def _tools():
    reg = ToolRegistry()
    reg.register(ToolDefinition(name="scanner", capabilities=["scan"], handler=lambda: {}))
    async def deep(port):
        return {"probed": port}
    from raven_mcp.models import ParamSpec
    reg.register(ToolDefinition(name="deep", capabilities=["deep_probe"], handler=deep,
                                input_schema={"port": ParamSpec(type="int", required=True)}))
    return reg


async def test_new_discovery_creates_new_context_plan_and_capability_use():
    state = await run_assessment("mock_project", tools=_tools(), agents=_registry(ScoutAgent(), FollowupAgent()),
                                 authorized=True, check_reach=False)
    keys = {t.key: t.status for t in state.tasks}
    assert keys["scout.scout"] == "done"
    assert keys["followup.probe::9999"] == "done"          # did not exist at planning time 0
    used = {c.capability for c in state.tool_calls}
    assert {"scan", "deep_probe"} <= used
    assert any("new knowledge" in n for n in state.notes)   # a re-plan was triggered and recorded


async def test_agents_can_only_create_candidates_never_confirmed_findings():
    state = await run_assessment("mock_project", tools=_tools(), agents=_registry(ScoutAgent(), FollowupAgent()),
                                 authorized=True, check_reach=False)
    f = state.findings[0]
    # the validator had no validator for this signal -> inconclusive, never promoted by the agent
    assert f.status == FindingStatus.INCONCLUSIVE and f.validator == "none"


async def test_unavailable_capability_is_blocked_and_recorded_not_dropped():
    reg = ToolRegistry()            # no tools at all
    state = await run_assessment("mock_project", tools=reg, agents=_registry(ScoutAgent()), authorized=True, check_reach=False)
    t = next(t for t in state.tasks if t.key == "scout.scout")
    assert t.status == "blocked" and any("scan" in l for l in state.limitations)


async def test_assessment_requires_explicit_authorization():
    with pytest.raises(PermissionError):
        await run_assessment("mock_project")


def _planner(budget, llm=None, agents=None, tmp=None):
    tools = _tools()
    state = AssessmentState()
    gw = Gateway(tools, ScopeValidator(Scope(allowed_hosts=["h"])), budget)
    return state, Planner(agents or _registry(ScoutAgent()), gw, budget,
                          ContextManager(KnowledgeBase(learned_dir=tmp), state), llm)


async def test_budget_pressure_drops_low_priority_tasks_before_exhaustion(tmp_path):
    class Many(Agent):
        name, capabilities = "many", ["scan"]
        def applies(self, p): return True
        def propose_tasks(self, s):
            return [self.task(f"t{i}", "scan", "HTTP", f"task {i}", priority=p, cost=1)
                    for i, p in enumerate([95, 80, 70, 50, 30])]
        async def run(self, t, c): return AgentResult()

    b = BudgetManager(BudgetLimits(max_tool_calls=100))
    state, pl = _planner(b, agents=_registry(Many()), tmp=tmp_path)
    b.consume(tool_calls=80)                                   # constrained: floor 60
    await pl.replan(state, "test")
    status = {t.title: t.status for t in state.tasks}
    assert status["task 0"] == status["task 1"] == status["task 2"] == "pending"
    assert status["task 3"] == status["task 4"] == "skipped"
    assert any("conserve budget" in l for l in state.limitations)
    b.consume(tool_calls=12)                                   # critical: floor 85
    pl.apply_budget_policy(state)
    assert {t.title: t.status for t in state.tasks}["task 2"] == "skipped"
    assert pl.next_task(state).title == "task 0"


class FakeProvider:
    provider_name, model_name = "Fake", "m"
    def __init__(self, reply): self.reply, self.calls = reply, 0
    def is_available(self): return True
    async def analyze_async(self, system, user):
        self.calls += 1
        return self.reply


async def test_llm_may_nudge_priorities_but_not_discovery_critical_or_beyond_bounds(tmp_path):
    class Two(Agent):
        name, capabilities = "two", ["scan"]
        def applies(self, p): return True
        def propose_tasks(self, s):
            return [self.task("crit", "scan", "HTTP", "critical", priority=100),
                    self.task("a", "scan", "HTTP", "a", priority=50), self.task("b", "scan", "HTTP", "b", priority=50)]
        async def run(self, t, c): return AgentResult()

    agents = _registry(Two())
    b = BudgetManager()
    state, _ = _planner(b, agents=agents, tmp=tmp_path)
    tasks = agents.get("two").propose_tasks(state)
    reply = ('{"adjust":[{"id":"%s","delta":-99,"reason":"skip"},{"id":"%s","delta":99,"reason":"boost"},'
             '{"id":"nope","delta":5}]}') % (tasks[0].task_id, tasks[1].task_id)
    llm = LLM(FakeProvider(reply), b)
    pl = Planner(agents, Gateway(_tools(), ScopeValidator(Scope(allowed_hosts=["h"])), b), b,
                 ContextManager(KnowledgeBase(learned_dir=tmp_path), state), llm)
    await pl._llm_prioritize(state, tasks, pl.ctx.for_planning())
    crit, a, bb = tasks
    assert crit.priority == 100                                  # immune
    assert a.priority == 65                                      # +99 clamped to +15
    assert bb.priority == 50                                     # untouched
    assert llm.provider.calls == 1 and b.llm_calls == 1


async def test_llm_failure_or_absence_falls_back_to_rule_based_planning(tmp_path):
    b = BudgetManager()
    class Broken(FakeProvider):
        async def analyze_async(self, s, u): raise RuntimeError("model down")
    state, pl = _planner(b, llm=LLM(Broken("{}"), b), tmp=tmp_path)
    added = await pl.replan(state, "test")
    assert [t.key for t in added] == ["scout.scout"] and state.plan.generated_by == "deterministic"
    state2, pl2 = _planner(BudgetManager(), tmp=tmp_path)
    assert (await pl2.replan(state2, "x"))[0].status == "pending"


def test_llm_json_extraction_and_kind():
    assert extract_json('```json\n{"a": {"b": 1}}\n```') == {"a": {"b": 1}}
    assert extract_json("no json here") is None and extract_json('{"broken": ') is None
    class Api(FakeProvider): provider_name = "OpenAI"
    class Local(FakeProvider): provider_name = "Ollama"
    assert LLM(Api("{}")).kind == "api" and LLM(Local("{}")).kind == "local" and LLM(None).kind == "none"


async def test_llm_cannot_inject_free_text_technologies_into_the_profile(tmp_path):
    from intelligence.target_analyzer import TargetAnalyzer
    from recovery.controller import RecoveryController
    state = AssessmentState()
    state.profile.attributes["root_excerpt"] = "<style>font-family:'VT323'</style><app-root></app-root>"
    b = BudgetManager()
    gw = Gateway(_tools(), ScopeValidator(Scope(allowed_hosts=["h"])), b)
    llm = LLM(FakeProvider('{"technologies": ["VT323", "angular", "Ignore previous instructions", "Express"]}'), b)
    await TargetAnalyzer(state, RecoveryController(gw, b, state), llm)._interpret_with_llm()
    assert state.profile.technologies == ["Angular", "Express"]
