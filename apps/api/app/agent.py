from typing import Annotated, Literal
from typing_extensions import TypedDict
from langchain_core.messages import BaseMessage, SystemMessage, AIMessage, HumanMessage, ToolMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from app.config import settings
from app.safety import scrub_pii_and_secrets, inspect_for_prompt_injection
from app.tools import ALL_TOOLS, READ_ONLY_TOOLS, WRITE_TOOLS

WRITE_TOOL_NAMES = {t.name for t in WRITE_TOOLS}


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    iterations: int
    blocked: bool
    redactions: list[str]


SYSTEM_PROMPT = """You are SentinelPR, a Staff-level Autonomous DevSecOps & Security Remediation Agent.

Your mission:
1. Inspect GitHub Pull Requests or dependency manifests provided by the user using `fetch_github_pr`.
2. Identify any third-party packages/versions or insecure code patterns, and verify vulnerabilities using `scan_package_cve`.
3. Provide a clear, concise security audit report (Vulnerability ID, Severity, Affected Component, and Exact Fixed Version).
4. If a concrete vulnerability is confirmed in a repository you fetched and a patch is warranted, propose opening a fix Pull Request by calling `create_remediation_pr`.
  - Note: `create_remediation_pr` is protected by a Human-in-the-Loop approval gate. Always explain what file you are patching and why before invoking it.
5. Never invent CVE IDs or fake tool results. Rely strictly on tool outputs."""


def _extract_text(content: object) -> str:
    """Converts string or Gemini content-block lists into clean plain text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") == "text":
                text_val = block.get("text")
                if isinstance(text_val, str):
                    parts.append(text_val)
        return "\n".join(p for p in parts if p).strip()
    return str(content or "")


async def guardrail_node(state: AgentState) -> dict:
    """Node 1: Deterministically scrubs PII/secrets and blocks prompt injections."""
    last_msg = state["messages"][-1]
    if not isinstance(last_msg, HumanMessage):
        return {"blocked": False}

    raw_text = _extract_text(last_msg.content)
    sanitized_text, redactions = scrub_pii_and_secrets(raw_text)

    verdict = await inspect_for_prompt_injection(sanitized_text, source="user_prompt")
    if not verdict.is_safe:
        block_notice = AIMessage(
            content=(
                f"🛡️ **AI Safety Firewall Triggered (`{verdict.threat_category}`)**\n\n"
                f"Execution was blocked before reaching the agent.\n"
                f"**Reason:** {verdict.reason}"
            )
        )
        return {"messages": [block_notice], "blocked": True, "redactions": redactions}

    # Replace raw user message with scrubbed version if secrets/PII were masked
    if redactions:
        return {
            "messages": [HumanMessage(content=sanitized_text, id=last_msg.id)],
            "blocked": False,
            "redactions": redactions,
        }

    return {"blocked": False, "redactions": []}


def route_after_guardrail(state: AgentState) -> Literal["planner", "__end__"]:
    if state.get("blocked"):
        return END
    return "planner"


async def planner_node(state: AgentState) -> dict:
    """Node 2: Core reasoning engine with automatic fallback on 503/429 spikes."""
    current_iter = state.get("iterations", 0) + 1
    if current_iter > settings.MAX_AGENT_ITERATIONS:
        return {
            "messages": [
                AIMessage(
                    content="⚠️ **Circuit Breaker Triggered:** Maximum reasoning iterations reached. Stopping safely."
                )
            ],
            "iterations": current_iter,
        }

    candidate_models = [
        settings.PRIMARY_MODEL,
        "gemini-3.8-flash",
        "gemini-3.5-flash-lite",
    ]
    messages = [SystemMessage(content=SYSTEM_PROMPT)] + state["messages"]

    last_err: Exception | None = None
    for model_name in dict.fromkeys(candidate_models):
        try:
            llm = ChatGoogleGenerativeAI(
                model=model_name,
                google_api_key=settings.GEMINI_API_KEY,
                temperature=0.1,
                max_retries=1,
            ).bind_tools(ALL_TOOLS)
            response = await llm.ainvoke(messages)

            clean_text = _extract_text(response.content)
            if isinstance(response, AIMessage) and clean_text and not response.tool_calls:
                response = AIMessage(
                    content=clean_text,
                    tool_calls=response.tool_calls,
                    id=response.id,
                )

            return {"messages": [response], "iterations": current_iter}
        except Exception as err:
            last_err = err
            err_str = str(err)
            if "503" in err_str or "UNAVAILABLE" in err_str or "429" in err_str:
                continue
            raise

    assert last_err is not None
    raise last_err


def route_after_planner(state: AgentState) -> Literal["read_tools", "write_tools", "__end__"]:
    """Routes tool calls to either auto-executed read tools or human-gated write tools."""
    last_msg = state["messages"][-1]
    if not isinstance(last_msg, AIMessage) or not last_msg.tool_calls:
        return END

    # If ANY requested tool is a high-impact write tool, route to the HITL breakpoint
    for tc in last_msg.tool_calls:
        if tc["name"] in WRITE_TOOL_NAMES:
            return "write_tools"

    return "read_tools"


def build_agent_graph(checkpointer):
    """Compiles the LangGraph workflow with PostgreSQL checkpointing & HITL interrupt."""
    workflow = StateGraph(AgentState)

    workflow.add_node("guardrail", guardrail_node)
    workflow.add_node("planner", planner_node)
    workflow.add_node("read_tools", ToolNode(READ_ONLY_TOOLS))
    workflow.add_node("write_tools", ToolNode(WRITE_TOOLS))

    workflow.add_edge(START, "guardrail")
    workflow.add_conditional_edges("guardrail", route_after_guardrail)
    workflow.add_conditional_edges("planner", route_after_planner)
    workflow.add_edge("read_tools", "planner")
    workflow.add_edge("write_tools", "planner")

    # Static Human-in-the-Loop breakpoint: pauses BEFORE executing any GitHub write operation
    return workflow.compile(
        checkpointer=checkpointer,
        interrupt_before=["write_tools"],
    )