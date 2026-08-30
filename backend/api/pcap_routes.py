"""
Passive PCAP/Zeek investigation API.

POST /api/pcap/upload  -- accepts a Zeek dns.log file (tab-separated,
the format `zeek -r capture.pcap` produces), runs it through the
tunnel-detection pipeline, and stores the summary for later retrieval.
This is the "passive path" described in the architecture:

    PCAP -> Zeek -> dns.log -> feature extraction -> same detection
    pipeline -> investigation dashboard

Requires analyst/admin role since uploaded files could be large or
sensitive.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File

from backend.auth.security import require_role
from backend.pcap.zeek_parser import analyze_zeek_log
from backend.utils.logger import get_logger

router = APIRouter(prefix="/api/pcap", tags=["pcap-investigation"])
logger = get_logger("pcap_routes")

MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5MB cap for the hackathon demo

# In-memory result store (swap for a DB table in production -- kept simple
# here since PCAP investigation results are typically short-lived/session-scoped)
_RESULTS_STORE: dict[str, dict] = {}


@router.post("/upload")
async def upload_pcap_log(
    file: UploadFile = File(...),
    user=Depends(require_role("admin", "analyst")),
):
    if not file.filename.endswith((".log", ".txt")):
        raise HTTPException(
            status_code=400,
            detail="Expected a Zeek dns.log file (.log or .txt). "
                   "Run `zeek -r capture.pcap` first to produce one.",
        )

    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 5MB for the demo)")

    raw_text = contents.decode("utf-8", errors="ignore")
    result = analyze_zeek_log(raw_text)

    result_id = str(uuid.uuid4())[:8]
    _RESULTS_STORE[result_id] = {"filename": file.filename, "uploaded_by": user.username, **result}

    logger.info(
        f"PCAP analysis {result_id}: {result['sessions_analyzed']} sessions, "
        f"{result['tunnel_suspected_sessions']} suspected tunnels (by {user.username})"
    )

    return {"id": result_id, **result}


@router.get("/{result_id}/results")
def get_pcap_results(result_id: str, user=Depends(require_role("admin", "analyst", "viewer"))):
    result = _RESULTS_STORE.get(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="No PCAP analysis found with that ID")
    return result


@router.get("/history")
def pcap_history(user=Depends(require_role("admin", "analyst", "viewer"))):
    return [
        {
            "id": rid,
            "filename": r["filename"],
            "sessions_analyzed": r["sessions_analyzed"],
            "tunnel_suspected_sessions": r["tunnel_suspected_sessions"],
        }
        for rid, r in _RESULTS_STORE.items()
    ]
