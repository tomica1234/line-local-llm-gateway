from __future__ import annotations

from ..storage import Storage
from ..types import TaskRecord, TaskState

TERMINAL_STATES = {
    TaskState.COMPLETED,
    TaskState.CANCELLED,
    TaskState.FAILED,
}

ALLOWED_TRANSITIONS: dict[TaskState, set[TaskState]] = {
    TaskState.RECEIVED: {
        TaskState.UNDERSTANDING,
        TaskState.PAUSED,
        TaskState.CANCELLED,
    },
    TaskState.UNDERSTANDING: {
        TaskState.PLANNING,
        TaskState.WAITING_USER,
        TaskState.FAILED,
        TaskState.CANCELLED,
        TaskState.PAUSED,
    },
    TaskState.PLANNING: {
        TaskState.EXECUTING,
        TaskState.WAITING_APPROVAL,
        TaskState.FAILED,
        TaskState.CANCELLED,
        TaskState.PAUSED,
    },
    TaskState.EXECUTING: {
        TaskState.VERIFYING,
        TaskState.WAITING_AUTH,
        TaskState.WAITING_APPROVAL,
        TaskState.WAITING_USER,
        TaskState.WAITING_EXTERNAL,
        TaskState.SUBMITTED_UNKNOWN,
        TaskState.RETRYING,
        TaskState.FAILED,
        TaskState.CANCELLED,
        TaskState.PAUSED,
    },
    TaskState.VERIFYING: {
        TaskState.COMPLETED,
        TaskState.RETRYING,
        TaskState.SUBMITTED_UNKNOWN,
        TaskState.FAILED,
        TaskState.CANCELLED,
        TaskState.PAUSED,
    },
    TaskState.RETRYING: {
        TaskState.EXECUTING,
        TaskState.FAILED,
        TaskState.PAUSED,
        TaskState.CANCELLED,
    },
    TaskState.WAITING_AUTH: {
        TaskState.UNDERSTANDING,
        TaskState.EXECUTING,
        TaskState.PAUSED,
        TaskState.CANCELLED,
    },
    TaskState.WAITING_APPROVAL: {
        TaskState.UNDERSTANDING,
        TaskState.EXECUTING,
        TaskState.PAUSED,
        TaskState.CANCELLED,
    },
    TaskState.WAITING_USER: {TaskState.UNDERSTANDING, TaskState.PAUSED, TaskState.CANCELLED},
    TaskState.WAITING_EXTERNAL: {
        TaskState.RETRYING,
        TaskState.PAUSED,
        TaskState.CANCELLED,
    },
    TaskState.SUBMITTED_UNKNOWN: {
        TaskState.VERIFYING,
        TaskState.PAUSED,
        TaskState.FAILED,
    },
    TaskState.PAUSED: {TaskState.UNDERSTANDING, TaskState.CANCELLED},
    TaskState.FAILED: {TaskState.UNDERSTANDING, TaskState.CANCELLED},
    TaskState.COMPLETED: set(),
    TaskState.CANCELLED: set(),
}


class InvalidTransition(ValueError):
    pass


class TaskStateMachine:
    def __init__(self, storage: Storage):
        self.storage = storage

    def transition(
        self,
        task_id: str,
        target: TaskState,
        *,
        event_type: str = "state_transition",
        payload: dict[str, object] | None = None,
    ) -> TaskRecord:
        current = self.storage.get_task(task_id)
        if target == current.state:
            return current
        allowed = ALLOWED_TRANSITIONS[current.state]
        if target not in allowed:
            raise InvalidTransition(
                f"Task {task_id}: {current.state.value} -> {target.value} is not allowed"
            )
        return self.storage.update_task(
            task_id,
            state=target,
            event_type=event_type,
            event_payload={"from": current.state.value, **(payload or {})},
        )
