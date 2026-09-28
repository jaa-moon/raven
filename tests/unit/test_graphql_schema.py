"""
Pure parsing of a GraphQL introspection response into testable operations --
no HTTP, no agent, just `core/graphql_schema.py::parse_introspection` against
hand-built introspection JSON. Complements the fixture-server integration
tests in `tests/integration/test_graphql_injection.py`, which prove the same
behavior end to end through the real discover -> test -> validate pipeline.
"""

from __future__ import annotations

from core.graphql_schema import parse_introspection

NON_NULL = lambda inner: {"kind": "NON_NULL", "name": None, "ofType": inner}  # noqa: E731
SCALAR = lambda name: {"kind": "SCALAR", "name": name, "ofType": None}  # noqa: E731
LIST = lambda inner: {"kind": "LIST", "name": None, "ofType": inner}  # noqa: E731
NAMED = lambda kind, name: {"kind": kind, "name": name, "ofType": None}  # noqa: E731


def _schema(query_fields=None, mutation_fields=None, extra_types=None):
    types = [
        {"kind": "OBJECT", "name": "Query", "fields": query_fields or [], "inputFields": None},
        {"kind": "OBJECT", "name": "Mutation", "fields": mutation_fields or [], "inputFields": None},
        *(extra_types or []),
    ]
    return {"queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"}, "types": types}


def test_scalar_argument_is_discovered_with_correct_type_and_evidence_shape():
    schema = _schema(query_fields=[
        {"name": "userById", "type": NAMED("OBJECT", "User"),
         "args": [{"name": "id", "type": NON_NULL(SCALAR("ID"))}]},
    ])
    parsed = parse_introspection(schema)
    assert parsed["skipped"] == []
    ops = parsed["operations"]
    assert len(ops) == 1
    op = ops[0]
    assert op["operation_type"] == "query" and op["field"] == "userById"
    assert op["top_level_args"] == {"id": "ID!"}
    assert op["baseline_variables"] == {"id": "1"}
    assert op["testable_leaves"] == [{"variable_path": "id", "variable_type": "ID!"}]


def test_list_argument_is_never_selected_for_injection_but_sibling_scalar_still_is():
    schema = _schema(query_fields=[
        {"name": "userById", "type": NAMED("OBJECT", "User"), "args": [
            {"name": "id", "type": NON_NULL(SCALAR("ID"))},
            {"name": "tags", "type": LIST(NON_NULL(SCALAR("String")))},   # optional list: must be excluded
        ]},
    ])
    parsed = parse_introspection(schema)
    assert parsed["skipped"] == []
    op = parsed["operations"][0]
    assert "tags" not in op["top_level_args"]
    assert "tags" not in op["baseline_variables"]
    assert [leaf["variable_path"] for leaf in op["testable_leaves"]] == ["id"]


def test_required_list_argument_makes_the_whole_field_unbuildable_and_is_recorded_skipped():
    schema = _schema(query_fields=[
        {"name": "search", "type": NAMED("OBJECT", "User"), "args": [
            {"name": "ids", "type": NON_NULL(LIST(NON_NULL(SCALAR("ID"))))},
        ]},
    ])
    parsed = parse_introspection(schema)
    assert parsed["operations"] == []
    assert parsed["skipped"] == ["query.search"]


def test_nested_input_object_with_multiple_scalar_types_is_fully_discovered():
    input_type = {"kind": "INPUT_OBJECT", "name": "CreateUserInput", "fields": None, "inputFields": [
        {"name": "name", "type": NON_NULL(SCALAR("String"))},
        {"name": "age", "type": NON_NULL(SCALAR("Int"))},
        {"name": "active", "type": NON_NULL(SCALAR("Boolean"))},
    ]}
    schema = _schema(
        mutation_fields=[
            {"name": "createUser", "type": NAMED("OBJECT", "User"),
             "args": [{"name": "input", "type": NON_NULL(NAMED("INPUT_OBJECT", "CreateUserInput"))}]},
        ],
        extra_types=[input_type],
    )
    parsed = parse_introspection(schema)
    assert parsed["skipped"] == []
    op = parsed["operations"][0]
    assert op["operation_type"] == "mutation" and op["field"] == "createUser"
    assert op["top_level_args"] == {"input": "CreateUserInput!"}
    assert op["baseline_variables"] == {"input": {"name": "raven1", "age": 1, "active": True}}
    leaves = {leaf["variable_path"]: leaf["variable_type"] for leaf in op["testable_leaves"]}
    assert leaves == {"input.name": "String!", "input.age": "Int!", "input.active": "Boolean!"}


def test_required_enum_or_unsupported_scalar_field_inside_an_input_object_skips_the_whole_field():
    input_type = {"kind": "INPUT_OBJECT", "name": "CreateUserInput", "fields": None, "inputFields": [
        {"name": "name", "type": NON_NULL(SCALAR("String"))},
        {"name": "role", "type": NON_NULL(NAMED("ENUM", "Role"))},     # required enum: unbuildable
    ]}
    schema = _schema(
        mutation_fields=[
            {"name": "createUser", "type": NAMED("OBJECT", "User"),
             "args": [{"name": "input", "type": NON_NULL(NAMED("INPUT_OBJECT", "CreateUserInput"))}]},
        ],
        extra_types=[input_type],
    )
    parsed = parse_introspection(schema)
    assert parsed["operations"] == []
    assert parsed["skipped"] == ["mutation.createUser"]


def test_optional_unsupported_custom_scalar_is_omitted_not_guessed():
    schema = _schema(query_fields=[
        {"name": "eventsSince", "type": NAMED("OBJECT", "Event"), "args": [
            {"name": "id", "type": NON_NULL(SCALAR("ID"))},
            {"name": "since", "type": NAMED("SCALAR", "DateTime")},    # optional custom scalar: omitted
        ]},
    ])
    parsed = parse_introspection(schema)
    assert parsed["skipped"] == []
    op = parsed["operations"][0]
    assert "since" not in op["top_level_args"]
    assert [leaf["variable_path"] for leaf in op["testable_leaves"]] == ["id"]


def test_field_with_no_testable_arguments_is_silently_excluded_not_skipped():
    schema = _schema(query_fields=[{"name": "ping", "type": SCALAR("String"), "args": []}])
    parsed = parse_introspection(schema)
    assert parsed["operations"] == []
    assert parsed["skipped"] == []           # nothing to test is not a failure


# ── graceful degradation on malformed/incomplete introspection ─────────────────

def test_missing_types_key_degrades_to_no_operations_without_crashing():
    schema = {"queryType": {"name": "Query"}, "mutationType": None}   # no "types" at all
    parsed = parse_introspection(schema)
    assert parsed == {"operations": [], "skipped": []}


def test_field_with_no_args_key_is_treated_as_zero_arguments():
    schema = _schema(query_fields=[{"name": "userById", "type": NAMED("OBJECT", "User")}])   # no "args" key
    parsed = parse_introspection(schema)
    assert parsed == {"operations": [], "skipped": []}


def test_non_dict_schema_never_raises():
    assert parse_introspection(None) == {"operations": [], "skipped": []}
    assert parse_introspection("not a schema") == {"operations": [], "skipped": []}
    assert parse_introspection({"types": "not a list"}) == {"operations": [], "skipped": []}


def test_malformed_field_and_arg_entries_are_skipped_not_crashed_on():
    schema = _schema(query_fields=[
        "not a dict",
        {"name": None, "args": []},                       # no name
        {"name": "userById", "type": NAMED("OBJECT", "User"), "args": [
            "also not a dict",
            {"name": None, "type": SCALAR("String")},      # arg with no name
            {"name": "id", "type": NON_NULL(SCALAR("ID"))},
        ]},
    ])
    parsed = parse_introspection(schema)
    assert parsed["skipped"] == []
    assert len(parsed["operations"]) == 1
    assert [leaf["variable_path"] for leaf in parsed["operations"][0]["testable_leaves"]] == ["id"]
