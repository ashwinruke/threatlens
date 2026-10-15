"""API endpoints for the threat knowledge graph."""
from fastapi import APIRouter, HTTPException, Query, Request

from app.knowledge import attack, cwe
from app.knowledge.models import EntityView, KnowledgeStats, SearchResult
from app.knowledge.repository import KnowledgeRepository
from app.knowledge.search import KINDS, search
from app.store import PostgresStore

router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])


def _repository(request: Request) -> KnowledgeRepository:
    store = request.app.state.store
    if not isinstance(store, PostgresStore):
        raise HTTPException(status_code=503, detail="The knowledge base needs the database, which isn't connected.")
    return KnowledgeRepository(store)


IMPORTS = {attack.SOURCE: ("MITRE ATT&CK", "import_attack"), cwe.SOURCE: ("MITRE CWE", "import_cwe")}


@router.get("/stats", response_model=KnowledgeStats)
async def knowledge_stats(request: Request, source: str = Query(attack.SOURCE, description="mitre-attack or mitre-cwe")):
    """Which version of a knowledge source is loaded, and how many entries of each kind."""
    if source not in IMPORTS:
        raise HTTPException(status_code=422, detail="Unknown source. Use: " + ", ".join(IMPORTS))
    stats = await _repository(request).stats(source)
    if not stats:
        name, script = IMPORTS[source]
        raise HTTPException(status_code=404, detail=f"No {name} data loaded yet. Run: python -m scripts.{script}")
    return stats


@router.get("/search", response_model=list[SearchResult])
async def knowledge_search(
    request: Request,
    q: str = Query(..., min_length=1, max_length=200, description="A name, alias, ID, or topic"),
    kind: str | None = Query(None, description="Only these kinds, comma-separated: " + ", ".join(sorted(KINDS))),
    limit: int = Query(10, ge=1, le=25),
):
    """Find ATT&CK entries by ID, name, alias, similar spelling, or description words."""
    repository = _repository(request)
    kinds = [k.strip().lower() for k in kind.split(",")] if kind else None
    if kinds and any(k not in KINDS for k in kinds):
        raise HTTPException(status_code=422, detail="Unknown kind. Use: " + ", ".join(sorted(KINDS)))
    return await search(repository.store, q, kinds, limit)


@router.get("/entities/{external_id}", response_model=EntityView)
async def knowledge_entity(external_id: str, request: Request):
    """One entry by its ATT&CK ID (like G1017, S0002, T1059.001), with everything connected to it."""
    view = await _repository(request).view(external_id.strip())
    if not view:
        raise HTTPException(status_code=404, detail=f"No ATT&CK or CWE entry with ID {external_id}.")
    return view
