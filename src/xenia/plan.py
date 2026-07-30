from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

PLAN_TOOLS = frozenset({
    "TodoWrite", "TodoRead", "todo_write",
    "TaskCreate", "TaskUpdate", "TaskList", "TaskGet",
    "update_plan", "UpdatePlan",
})

_STATUS = {
    "pending": "pending", "todo": "pending", "not_started": "pending",
    "open": "pending", "queued": "pending",
    "in_progress": "in_progress", "in-progress": "in_progress",
    "inprogress": "in_progress", "active": "in_progress",
    "started": "in_progress", "running": "in_progress",
    "completed": "completed", "complete": "completed", "done": "completed",
    "finished": "completed", "resolved": "completed",
    "deleted": "dropped", "cancelled": "dropped", "canceled": "dropped",
    "dropped": "dropped", "abandoned": "dropped", "skipped": "dropped",
}

LABEL_LIMIT = 300


@dataclass
class PlanItem:
    label: str
    status: str = "pending"
    external_id: str | None = None


@dataclass
class Plan:
    items: list[PlanItem] = field(default_factory=list)
    whole_list: bool = False


def is_plan_tool(tool: str | None) -> bool:
    return (tool or "") in PLAN_TOOLS


def normalise_status(value: Any) -> str:
    return _STATUS.get(str(value or "").strip().lower(), "pending")


def label_key(label: str) -> str:
    return " ".join(str(label or "").lower().split())[:LABEL_LIMIT]


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _item(label: Any, status: Any, external_id: Any = None) -> PlanItem | None:
    text = _text(label)
    if not text:
        return None
    return PlanItem(
        label=text[:LABEL_LIMIT],
        status=normalise_status(status),
        external_id=_text(external_id) or None,
    )


def read(tool: str | None, args: Any, response: Any = None) -> Plan | None:
    if not is_plan_tool(tool) or not isinstance(args, dict):
        return None

    for key in ("todos", "plan", "items", "steps", "tasks"):
        listed = args.get(key)
        if isinstance(listed, list):
            items = []
            for entry in listed:
                if isinstance(entry, dict):
                    made = _item(
                        entry.get("content") or entry.get("step")
                        or entry.get("subject") or entry.get("task")
                        or entry.get("title") or entry.get("description"),
                        entry.get("status"),
                        entry.get("id") or entry.get("taskId"),
                    )
                elif isinstance(entry, str):
                    made = _item(entry, "pending")
                else:
                    made = None
                if made is not None:
                    items.append(made)
            return Plan(items=items, whole_list=True)

    if tool == "TaskCreate":
        made = _item(args.get("subject") or args.get("title")
                     or args.get("description"),
                     args.get("status") or "pending",
                     _created_id(response))
        return Plan(items=[made] if made else [])

    if tool == "TaskUpdate":
        external = _text(args.get("taskId") or args.get("task_id") or args.get("id"))
        status = args.get("status")
        made = _item(args.get("subject") or args.get("title") or external,
                     status, external)
        if made is None or (not external and not status):
            return Plan(items=[])
        if not args.get("subject") and not args.get("title"):
            made.label = ""
        return Plan(items=[made])

    return None


def _created_id(response: Any) -> str | None:
    if isinstance(response, dict):
        made = response.get("task")
        if isinstance(made, dict) and made.get("id") is not None:
            return _text(made.get("id"))
        for key in ("taskId", "task_id", "id"):
            if response.get(key) is not None:
                return _text(response.get(key))
    return None
