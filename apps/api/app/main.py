import json
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from psycopg_pool import AsyncConnectionPool
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langchain_core.messages import HumanMessage, ToolMessage, AIMessage
import redis.asyncio as redis
from sse_starlette.sse import EventSourceResponse

from app.config import settings
from app.agent import build_agent_graph


# --- Request / Response Schemas ---

class ChatRequest(BaseModel):
    thread_id: str = Field(..., min_length=3, max_length=100)
    message: str = Field(..., min_length=1, max_length=8000)


class ApprovalRequest(BaseModel):
    thread_id: str = Field(..., min_length=3, max_length=100)
    approved: bool
    feedback: str = Field(default="", max_length=1000)


# --- App Lifespan (Postgres Connection Pool + Redis) ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize PostgreSQL connection pool with autocommit required by AsyncPostgresSaver
    pool = AsyncConnectionPool(
        conninfo=settings.DATABASE_URL,
        max_size=10,
        kwargs={"autocommit": True, "prepare_threshold": 0},
        open=False,
    )
    await pool.open()

    checkpointer = AsyncPostgresSaver(pool)
    await checkpointer.setup()

    app.state.pool = pool
    app.state.graph = build_agent_graph(checkpointer)
    app.state.redis = redis.from_url(settings.REDIS_URL, decode_responses=True)

    yield

    await app.state.redis.aclose()
    await pool.close()


app = FastAPI(
    title="SentinelPR Autonomous Security Agent API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def enforce_rate_limit(request: Request):
    """Redis per-IP rate limiter to prevent wallet-drain attacks."""
    client_ip = request.client.host if request.client else "unknown"
    key = f"ratelimit:{client_ip}:{int(time.time() // 60)}"
    try:
        count = await app.state.redis.incr(key)
        if count == 1:
            await app.state.redis.expire(key, 60)
        if count > settings.RATE_LIMIT_REQUESTS_PER_MINUTE:
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Please wait 60 seconds before sending more requests.",
            )
    except HTTPException:
        raise
    except Exception:
        pass  # Fail-open on Redis network blip so legitimate traffic isn't dropped


def _sse_event(event_type: str, data: dict) -> dict:
    return {"event": event_type, "data": json.dumps(data)}


async def _stream_graph_execution(graph, input_payload, config: dict):
    """Streams live LangGraph node transitions, tool calls, and HITL interrupts over SSE."""
    start_time = time.perf_counter()

    try:
        async for event in graph.astream(input_payload, config=config, stream_mode="updates"):
            elapsed_ms = round((time.perf_counter() - start_time) * 1000)

            for node_name, node_output in event.items():
                yield _sse_event(
                    "node_update",
                    {"node": node_name, "elapsed_ms": elapsed_ms},
                )

                if not isinstance(node_output, dict):
                    continue

                # Notify UI if PII or secrets were scrubbed
                if node_output.get("redactions"):
                    yield _sse_event(
                        "security_redaction",
                        {"redactions": node_output["redactions"], "elapsed_ms": elapsed_ms},
                    )

                for msg in node_output.get("messages", []):
                    # Tool invocation requested by planner
                    if isinstance(msg, AIMessage) and msg.tool_calls:
                        for tc in msg.tool_calls:
                            yield _sse_event(
                                "tool_call",
                                {
                                    "tool_name": tc["name"],
                                    "tool_args": tc["args"],
                                    "tool_call_id": tc["id"],
                                    "elapsed_ms": elapsed_ms,
                                },
                            )

                    # Tool execution output
                    elif isinstance(msg, ToolMessage):
                        yield _sse_event(
                            "tool_result",
                            {
                                "tool_name": msg.name,
                                "output": str(msg.content)[:2500],
                                "elapsed_ms": elapsed_ms,
                            },
                        )

                    # Final or intermediate assistant text response
                    elif isinstance(msg, AIMessage) and msg.content:
                        yield _sse_event(
                            "message",
                            {
                                "content": str(msg.content),
                                "elapsed_ms": elapsed_ms,
                            },
                        )

        # Check if graph paused at the Human-in-the-Loop breakpoint (`write_tools`)
        snapshot = await graph.aget_state(config)
        if snapshot.next and "write_tools" in snapshot.next:
            last_msg = snapshot.values["messages"][-1]
            pending_calls = getattr(last_msg, "tool_calls", [])
            yield _sse_event(
                "approval_required",
                {
                    "node": "write_tools",
                    "pending_tools": pending_calls,
                    "elapsed_ms": round((time.perf_counter() - start_time) * 1000),
                },
            )
        else:
            yield _sse_event(
                "done",
                {"elapsed_ms": round((time.perf_counter() - start_time) * 1000)},
            )

    except Exception as e:
        yield _sse_event("error", {"message": str(e)})


# --- API Endpoints ---

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "primary_model": settings.PRIMARY_MODEL,
        "guardrail_model": settings.FAST_GUARDRAIL_MODEL,
    }


@app.post("/api/chat/stream")
async def chat_stream(req: ChatRequest, request: Request):
    await enforce_rate_limit(request)
    config = {"configurable": {"thread_id": req.thread_id}}
    input_payload = {
        "messages": [HumanMessage(content=req.message)],
        "iterations": 0,
        "blocked": False,
        "redactions": [],
    }
    return EventSourceResponse(_stream_graph_execution(app.state.graph, input_payload, config))


@app.post("/api/chat/approve")
async def approve_tool_execution(req: ApprovalRequest, request: Request):
    await enforce_rate_limit(request)
    graph = app.state.graph
    config = {"configurable": {"thread_id": req.thread_id}}

    snapshot = await graph.aget_state(config)
    if not snapshot.next or "write_tools" not in snapshot.next:
        raise HTTPException(status_code=400, detail="No pending write action awaiting approval for this thread.")

    if req.approved:
        # Passing None resumes execution right at the paused `write_tools` node
        return EventSourceResponse(_stream_graph_execution(graph, None, config))

    # If rejected by human, inject a ToolMessage cancellation and resume planner gracefully
    last_msg = snapshot.values["messages"][-1]
    rejection_messages = [
        ToolMessage(
            tool_call_id=tc["id"],
            name=tc["name"],
            content=(
                f"HUMAN_REJECTED: The user explicitly rejected executing `{tc['name']}`. "
                f"User note: {req.feedback or 'No reason provided'}. "
                "Do NOT retry this write tool; summarize your findings instead."
            ),
        )
        for tc in getattr(last_msg, "tool_calls", [])
    ]
    await graph.aupdate_state(config, {"messages": rejection_messages}, as_node="write_tools")
    return EventSourceResponse(_stream_graph_execution(graph, None, config))