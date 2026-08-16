from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..tool_broker.broker import ToolContext, ToolDefinition
from ..types import RiskLevel, ToolResult
from .client import HomeAssistantClient

_LOW_RISK_TOGGLE_DOMAINS = {
    "climate",
    "fan",
    "humidifier",
    "input_boolean",
    "light",
    "media_player",
    "switch",
}


class EntityArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entity_id: str = Field(pattern=r"^[a-z_]+\.[a-z0-9_]+$", max_length=255)


class TemperatureArgs(EntityArgs):
    temperature: float = Field(ge=5, le=35)


class SceneArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entity_id: str = Field(pattern=r"^scene\.[a-z0-9_]+$", max_length=255)


def home_tools(client: HomeAssistantClient) -> list[ToolDefinition[Any]]:
    async def get_state(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = EntityArgs.model_validate(args)
        return ToolResult(status="ok", evidence=await client.get_state(parsed.entity_id))

    def service_handler(service: str):
        async def execute(args: BaseModel, _context: ToolContext) -> ToolResult:
            parsed = EntityArgs.model_validate(args)
            domain = parsed.entity_id.split(".", 1)[0]
            if domain in {"alarm_control_panel", "lock"}:
                raise PermissionError(
                    "Security-critical Home Assistant entities require a strong-auth adapter"
                )
            if domain not in _LOW_RISK_TOGGLE_DOMAINS:
                raise PermissionError("Home Assistant domain is not enabled for toggling")
            evidence = await client.call_service(domain, service, {"entity_id": parsed.entity_id})
            return ToolResult(status="ok", reversible=True, evidence=evidence)

        return execute

    async def set_temperature(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = TemperatureArgs.model_validate(args)
        if not parsed.entity_id.startswith("climate."):
            raise ValueError("Temperature can only target climate entities")
        evidence = await client.call_service(
            "climate",
            "set_temperature",
            {"entity_id": parsed.entity_id, "temperature": parsed.temperature},
        )
        return ToolResult(status="ok", reversible=True, evidence=evidence)

    async def run_scene(args: BaseModel, _context: ToolContext) -> ToolResult:
        parsed = SceneArgs.model_validate(args)
        client.assert_safe_scene(parsed.entity_id)
        evidence = await client.call_service("scene", "turn_on", {"entity_id": parsed.entity_id})
        return ToolResult(status="ok", reversible=False, evidence=evidence)

    return [
        ToolDefinition(
            name="home.get_state",
            description="Read one exact Home Assistant entity state.",
            args_model=EntityArgs,
            handler=get_state,
            risk_level=RiskLevel.R0,
        ),
        ToolDefinition(
            name="home.turn_on",
            description="Turn on one exact Home Assistant entity.",
            args_model=EntityArgs,
            handler=service_handler("turn_on"),
            risk_level=RiskLevel.R1,
            mutation=True,
        ),
        ToolDefinition(
            name="home.turn_off",
            description="Turn off one exact Home Assistant entity.",
            args_model=EntityArgs,
            handler=service_handler("turn_off"),
            risk_level=RiskLevel.R1,
            mutation=True,
        ),
        ToolDefinition(
            name="home.set_temperature",
            description="Set a bounded temperature on one climate entity.",
            args_model=TemperatureArgs,
            handler=set_temperature,
            risk_level=RiskLevel.R1,
            mutation=True,
        ),
        ToolDefinition(
            name="home.run_scene",
            description="Run one exact Home Assistant scene.",
            args_model=SceneArgs,
            handler=run_scene,
            risk_level=RiskLevel.R2,
            mutation=True,
        ),
    ]
