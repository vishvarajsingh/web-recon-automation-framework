from fastapi import APIRouter, HTTPException
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..security import require_api_key

router = APIRouter(prefix="/chat", tags=["chat"])
router = APIRouter(prefix="/chat", tags=["chat"], dependencies=[Depends(require_api_key)])


class ChatRequest(BaseModel):
    messages: list[dict[str, str]]


class ChatResponse(BaseModel):
    response: str


@router.post("/", response_model=ChatResponse)
def chat(payload: ChatRequest):
    if not payload.messages:
        raise HTTPException(status_code=400, detail="Messages are required")

    return {"response": "AI chat functionality is not yet implemented. Use the structured report data API for now."}
