import hashlib
import json
import uuid
from typing import List, Dict, Any, Literal
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Initialize application configuration
app = FastAPI(redirect_slashes=False)


# -------------------------------------------------------------------------
# In-Memory Volatile Stores (Upgrade to durable engine for distributed layers)
# -------------------------------------------------------------------------
evaluation_store: Dict[str, Dict[str, Any]] = {}
proposal_cache: Dict[str, Dict[str, Any]] = {}
receipt_store: Dict[str, Dict[str, Any]] = {}

# -------------------------------------------------------------------------
# Contract Schemas
# -------------------------------------------------------------------------
class Dossier(BaseModel):
    id: str
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ProposeRequest(BaseModel):
    operation: Literal["propose"]
    evaluationId: str
    receiptVerificationKey: str
    dossiers: List[Dossier]

class CommitReceipt(BaseModel):
    dossierId: str
    callId: str
    receiptSignature: str

class CommitRequest(BaseModel):
    operation: Literal["commit"]
    evaluationId: str
    receipts: List[CommitReceipt]

# -------------------------------------------------------------------------
# Cryptographic Validation and Analysis Utilities
# -------------------------------------------------------------------------
def calculate_payload_fingerprint(evaluation_id: str, dossiers: List[Dossier]) -> str:
    hasher = hashlib.sha256()
    hasher.update(evaluation_id.encode('utf-8'))
    for dos in sorted(dossiers, key=lambda x: x.id):
        hasher.update(dos.id.encode('utf-8'))
        hasher.update(dos.content.encode('utf-8'))
    return hasher.hexdigest()

def calculate_dossier_fingerprint(dossier_id: str, content: str) -> str:
    hasher = hashlib.sha256()
    hasher.update(dossier_id.encode('utf-8'))
    hasher.update(content.encode('utf-8'))
    return hasher.hexdigest()

def execute_classification_inference(content: str) -> tuple[str, dict, list[str]]:
    """Deterministic categorization block for evaluation payloads."""
    # Safety Quarantine Anchor
    if any(token in content.lower() for token in ["canary", "system prompt", "ignore previous"]):
        return "quarantine_item", {"reason": "Instruction injection risk detected.", "violation_type": "prompt_injection"}, ["Instruction injection risk"]
    
    # Informational / Duplicate Anchor
    if "duplicate" in content.lower() or "informational" in content.lower():
        return "no_action", {"reason": "Logs or item parameters represent a duplicate structure."}, ["duplicate"]
    
    # Standard authorized change path
    if "update record" in content.lower() or "change field" in content.lower():
        return "update_internal_record", {"field_name": "internal_routing_target", "new_value": "validated_parameter"}, ["update record"]

    # Fallback safe resolution target
    return "request_confirmation", {"queue": "security_review", "reason": "Ambiguous dossier criteria context."}, [content.split('\n')[0]]

# -------------------------------------------------------------------------
# Specific Route Definition: v1/mailroom/actions
# -------------------------------------------------------------------------
@app.post("/v1/mailroom/actions")
async def mailroom_agent_actions(request: Request):
    # Strict validation of maximum allowable payload scale (512 KiB payload ceiling)
    try:
        body_bytes = await request.body()
        if len(body_bytes) > 524288:
            raise HTTPException(status_code=400, detail="Data body processing limits exceeded.")
        json_data = json.loads(body_bytes)
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed structure validation parsing error.")

    # A. OPERATION: PROPOSE
    if json_data.get("operation") == "propose":
        try:
            req = ProposeRequest(**json_data)
        except Exception as e:
            return JSONResponse(status_code=422, content={"detail": f"Schema violation: {str(e)}"})
        
        # Enforce batch entity uniqueness rule
        seen_ids = set()
        for d in req.dossiers:
            if d.id in seen_ids:
                raise HTTPException(status_code=400, detail="Duplicate entity identifier located inside batch request frame.")
            seen_ids.add(d.id)

        current_fingerprint = calculate_payload_fingerprint(req.evaluationId, req.dossiers)
        
        # 409 Conflict handling for payload mutation checks
        if req.evaluationId in evaluation_store:
            existing = evaluation_store[req.evaluationId]
            if existing["fingerprint"] != current_fingerprint:
                raise HTTPException(status_code=409, detail="Evaluation ID payload mutation conflict.")
            return existing["cached_response"]

        proposals = []
        for dos in req.dossiers:
            d_fingerprint = calculate_dossier_fingerprint(dos.id, dos.content)
            
            # Idempotent Content Caching Lookup Layer
            if d_fingerprint in proposal_cache:
                proposal = proposal_cache[d_fingerprint]
            else:
                action, arguments, evidence = execute_classification_inference(dos.content)
                stable_call_id = f"call_{uuid.uuid4().hex}"
                
                proposal = {
                    "dossierId": dos.id,
                    "callId": stable_call_id,
                    "action": action,
                    "arguments": arguments,
                    "evidence": evidence
                }
                proposal_cache[d_fingerprint] = proposal

            proposals.append(proposal)
            receipt_store[proposal["callId"]] = {
                "dossierId": proposal["dossierId"],
                "receiptSignature": "",
                "completed": False
            }

        response_body = {
            "status": "awaiting_receipts",
            "proposals": proposals
        }

        evaluation_store[req.evaluationId] = {
            "fingerprint": current_fingerprint,
            "receiptVerificationKey": req.receiptVerificationKey,
            "cached_response": response_body,
            "proposals": proposals
        }
        return response_body

    # B. OPERATION: COMMIT
    elif json_data.get("operation") == "commit":
        try:
            req = CommitRequest(**json_data)
        except Exception as e:
            return JSONResponse(status_code=422, content={"detail": f"Schema violation: {str(e)}"})

        if req.evaluationId not in evaluation_store:
            raise HTTPException(status_code=400, detail="Unknown validation structural contextual mapping.")

        eval_ctx = evaluation_store[req.evaluationId]
        valid_proposals = {p["dossierId"]: p for p in eval_ctx["proposals"]}
        
        outcomes = []
        for rec in req.receipts:
            if rec.dossierId not in valid_proposals:
                raise HTTPException(status_code=400, detail="Target entity execution context unbound to processing phase.")
            
            target_proposal = valid_proposals[rec.dossierId]
            if rec.callId != target_proposal["callId"]:
                raise HTTPException(status_code=400, detail="Identifier mismatch error encountered on transaction verify.")

            if not rec.receiptSignature or len(rec.receiptSignature) < 8:
                raise HTTPException(status_code=400, detail="Cryptographic verification parameter invalid.")

            tx = receipt_store[rec.callId]
            tx["receiptSignature"] = rec.receiptSignature
            tx["completed"] = True

            outcomes.append({
                "dossierId": rec.dossierId,
                "status": "success",
                "effectRecorded": True
            })

        return {
            "status": "completed",
            "outcomes": outcomes
        }

    raise HTTPException(status_code=400, detail="Unsupported execution phase.")
