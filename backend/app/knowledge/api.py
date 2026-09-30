"""API endpoints for the threat knowledge graph."""
from fastapi import APIRouter, HTTPException, Request

from app.knowledge.attack import SOURCE
from app.knowledge.models import EntityView, KnowledgeStats
from app.knowledge.repository import KnowledgeRepository
from app.store import PostgresStore

router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])


def _repository(request: Request) -> KnowledgeRepository:
    store = request.app.state.store
    if not isinstance(store, PostgresStore):
        raise HTTPException(status_code=503, detail="The knowledge base needs the database, which isn't connected.")
    return KnowledgeRepository(store)


@router.get("/stats", response_model=KnowledgeStats)
async def knowledge_stats(request: Request):
    """Which ATT&CK version is loaded, and how many entries of each kind."""
    stats = await _repository(request).stats(SOURCE)
    if not stats:
        raise HTTPException(status_code=404,
                            detail="No ATT&CK data loaded yet. Run: python -m scripts.import_attack")
    return stats


@router.get("/entities/{external_id}", response_model=EntityView)
async def knowledge_entity(external_id: str, request: Request):
    """One entry by its ATT&CK ID (like G1017, S0002, T1059.001), with everything connected to it."""
    view = await _repository(request).view(external_id.strip())
    if not view:
        raise HTTPException(status_code=404, detail=f"No ATT&CK entry with ID {external_id}.")
    return view
