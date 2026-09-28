"""
core/graphql_schema.py
-----------------------
Pure parsing of a full GraphQL introspection response (see
`agents/web_recon.py::_graphql_schema`) into a bounded, JSON-serializable list
of testable "operations": for each query/mutation root field, which top-level
arguments -- and, for a nested `INPUT_OBJECT` argument, which scalar leaf
fields inside it -- are safe to vary one at a time while keeping every
sibling argument/field at a syntactically valid baseline value.

No I/O and no crashes here: the caller hands this module whatever JSON came
back from the target (which may be perfectly normal, missing keys the caller
expected, or actively hostile), and it always degrades to fewer discovered
operations rather than raising or fabricating one. This mirrors
`core/injection_signals.py`'s contract of pure, side-effect-free
interpretation shared by agent-side discovery and (indirectly, via the data
it produces) independent validation.

Scope, deliberately:
  * Only SCALAR leaf arguments (String/Int/Float/Boolean/ID) -- top-level or
    nested one or more levels inside an INPUT_OBJECT -- are ever treated as
    testable. A LIST or an OBJECT/INTERFACE/UNION/ENUM-typed argument is
    never injected into as a single string value.
  * A field is only included if EVERY argument (and, recursively, every
    nested input-object field) is either a supported scalar we can default,
    a resolvable INPUT_OBJECT, an optional argument we can safely omit, or a
    testable scalar. A REQUIRED argument of an unsupported shape (list, enum,
    unresolvable/custom scalar) makes the whole field's request unbuildable
    with confidence, so the field is skipped rather than guessed at.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

KNOWN_SCALARS = {"String", "Int", "Float", "Boolean", "ID"}
MAX_INPUT_DEPTH = 4   # bound on nested INPUT_OBJECT recursion (guards cycles/self-reference too)


def _as_dict(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _unwrap(type_ref: Any) -> Tuple[bool, bool, str, str]:
    """Peel a GraphQL TypeRef's wrapper chain: at most one outer NON_NULL,
    then at most one LIST (itself optionally NonNull-wrapped inside).

    Returns (required, is_list, named_kind, named_name). Anything deeper or
    differently shaped (double-wrapped lists, a chain longer than the
    introspection query's own bounded depth captured) collapses to an empty
    named_kind, which callers treat as unsupported -- never guessed at.
    """
    t = _as_dict(type_ref)
    required = False
    if t.get("kind") == "NON_NULL":
        required = True
        t = _as_dict(t.get("ofType"))
    is_list = False
    if t.get("kind") == "LIST":
        is_list = True
        t = _as_dict(t.get("ofType"))
        if t.get("kind") == "NON_NULL":
            t = _as_dict(t.get("ofType"))
    return required, is_list, str(t.get("kind") or ""), str(t.get("name") or "")


def _baseline_scalar(named: str) -> Any:
    return {"String": "raven1", "ID": "1", "Int": 1, "Float": 1.0, "Boolean": True}.get(named, "raven1")


def _resolve_input_object(
    type_name: str, types_by_name: Dict[str, Dict[str, Any]], prefix: str, depth: int, visited: Set[str],
) -> Optional[Tuple[Dict[str, Any], List[Tuple[str, str]]]]:
    """None means this input object cannot be safely, fully defaulted (a
    required field has a list/enum/object/unresolvable-scalar type, a cycle,
    malformed schema data, or the recursion bound was hit). Otherwise
    (baseline_dict, [(dotted_variable_path, graphql_type_str), ...])."""
    if depth <= 0 or type_name in visited:
        return None
    td = types_by_name.get(type_name)
    if not isinstance(td, dict) or td.get("kind") != "INPUT_OBJECT":
        return None
    visited = visited | {type_name}
    baseline: Dict[str, Any] = {}
    leaves: List[Tuple[str, str]] = []
    for fld in td.get("inputFields") or []:
        if not isinstance(fld, dict):
            continue
        fname = fld.get("name")
        if not fname:
            continue
        required, is_list, kind, named = _unwrap(fld.get("type"))
        dotted = f"{prefix}.{fname}" if prefix else str(fname)
        if is_list:
            if required:
                return None
            continue                                    # optional list: safely omitted
        if kind == "SCALAR":
            if named not in KNOWN_SCALARS:
                if required:
                    return None
                continue                                 # optional unsupported/custom scalar: omitted
            baseline[fname] = _baseline_scalar(named)
            leaves.append((dotted, named + ("!" if required else "")))
        elif kind == "INPUT_OBJECT":
            sub = _resolve_input_object(named, types_by_name, dotted, depth - 1, visited)
            if sub is None:
                if required:
                    return None
                continue
            sub_baseline, sub_leaves = sub
            baseline[fname] = sub_baseline
            leaves.extend(sub_leaves)
        else:                                            # ENUM / OBJECT / INTERFACE / UNION / unresolved
            if required:
                return None
            continue
    return baseline, leaves


def _fields_for(type_name: Optional[str], types_by_name: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not type_name:
        return []
    td = types_by_name.get(type_name)
    if not isinstance(td, dict):
        return []
    return [f for f in (td.get("fields") or []) if isinstance(f, dict)]


def parse_introspection(schema: Any) -> Dict[str, Any]:
    """Parse a full introspection `__schema` object into
    ``{"operations": [...], "skipped": [...]}``.

    Each operation: ``{"operation_type", "field", "top_level_args"
    (name -> GraphQL type string), "baseline_variables" (name -> safe default,
    nested dicts for input objects), "testable_leaves" (list of
    {"variable_path" (dotted), "variable_type"})}``.

    ``skipped`` lists ``"<operation_type>.<field>"`` for fields that have at
    least one REQUIRED argument whose type could not be safely defaulted
    (list, enum, unresolvable/custom scalar) -- a field is never included
    with a guessed value. Fields with zero testable scalar leaves (e.g. no
    arguments at all) are silently left out of both lists: that is not a
    limitation, just nothing to test.

    Never raises: a missing ``types`` key, a field with no ``args``, or any
    other incomplete/malformed shape degrades to fewer operations, never a
    crash and never a fabricated one.
    """
    schema = _as_dict(schema)
    types = schema.get("types")
    types_by_name: Dict[str, Dict[str, Any]] = {}
    for t in (types if isinstance(types, list) else []):
        if isinstance(t, dict) and t.get("name"):
            types_by_name[str(t["name"])] = t

    query_type = _as_dict(schema.get("queryType")).get("name")
    mutation_type = _as_dict(schema.get("mutationType")).get("name")

    operations: List[Dict[str, Any]] = []
    skipped: List[str] = []

    for op_type, type_name in (("query", query_type), ("mutation", mutation_type)):
        for field in _fields_for(type_name, types_by_name):
            fname = field.get("name")
            if not fname:
                continue
            top_level_args: Dict[str, str] = {}
            baseline_variables: Dict[str, Any] = {}
            leaves: List[Tuple[str, str]] = []
            buildable = True
            for arg in (field.get("args") or []):
                if not isinstance(arg, dict):
                    continue
                aname = arg.get("name")
                if not aname:
                    continue
                required, is_list, kind, named = _unwrap(arg.get("type"))
                if is_list:
                    if required:
                        buildable = False
                        break
                    continue
                if kind == "SCALAR":
                    if named not in KNOWN_SCALARS:
                        if required:
                            buildable = False
                            break
                        continue
                    top_level_args[aname] = named + ("!" if required else "")
                    baseline_variables[aname] = _baseline_scalar(named)
                    leaves.append((str(aname), named + ("!" if required else "")))
                elif kind == "INPUT_OBJECT":
                    sub = _resolve_input_object(named, types_by_name, str(aname), MAX_INPUT_DEPTH, set())
                    if sub is None:
                        if required:
                            buildable = False
                            break
                        continue
                    sub_baseline, sub_leaves = sub
                    top_level_args[aname] = named + ("!" if required else "")
                    baseline_variables[aname] = sub_baseline
                    leaves.extend(sub_leaves)
                else:                                     # ENUM / OBJECT / INTERFACE / UNION / unresolved
                    if required:
                        buildable = False
                        break
                    continue
            if not buildable:
                skipped.append(f"{op_type}.{fname}")
                continue
            if not leaves:
                continue
            operations.append({
                "operation_type": op_type, "field": str(fname),
                "top_level_args": top_level_args, "baseline_variables": baseline_variables,
                "testable_leaves": [{"variable_path": p, "variable_type": t} for p, t in leaves],
            })
    return {"operations": operations, "skipped": skipped}
