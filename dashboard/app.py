from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .database import get_db, init_db, seed_default_payloads
from .serial_manager import SerialManager

BASE_DIR = Path(__file__).resolve().parent
serial_manager = SerialManager()

VALID_CATEGORIES = [
    "wifi_cmd", "wifi_overflow", "wifi_fmt", "wifi_probe",
    "wifi_esc", "wifi_serial", "wifi_enc", "wifi_chain", "wifi_heap",
    "custom",
]
VALID_STATUSES = ["crashed", "rebooted", "survived", "unknown"]


# -- Lifespan --------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_default_payloads()
    yield
    await serial_manager.stop()


app = FastAPI(title="CommandInWiFi Dashboard", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


# -- HTML ------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index():
    return (BASE_DIR / "templates" / "index.html").read_text()


# -- Pydantic models -------------------------------------------------------

class PayloadCreate(BaseModel):
    text: str
    category: str
    description: str = ""

class PayloadUpdate(BaseModel):
    text: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None

class ResultCreate(BaseModel):
    payload_id: int
    device_name: str
    device_mac: str = ""
    status: str
    notes: str = ""

class SerialConnect(BaseModel):
    port: str
    baud: int = 115200

class DeployRequest(BaseModel):
    payload_ids: list[int]

class FlashRequest(BaseModel):
    port: str
    board: str = "esp32"  # "esp32" or "esp8266"


# -- Payload CRUD ----------------------------------------------------------

@app.get("/api/payloads")
def list_payloads(category: Optional[str] = Query(None)):
    conn = get_db()
    if category:
        rows = conn.execute(
            "SELECT * FROM payloads WHERE category = ? ORDER BY created_at DESC",
            (category,),
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM payloads ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/payloads", status_code=201)
def create_payload(payload: PayloadCreate):
    if payload.category not in VALID_CATEGORIES:
        raise HTTPException(400, f"Invalid category. Must be one of: {VALID_CATEGORIES}")
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO payloads (text, category, description) VALUES (?, ?, ?)",
        (payload.text, payload.category, payload.description),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM payloads WHERE id = ?", (cur.lastrowid,)).fetchone()
    conn.close()
    return dict(row)


@app.put("/api/payloads/{payload_id}")
def update_payload(payload_id: int, payload: PayloadUpdate):
    conn = get_db()
    existing = conn.execute("SELECT * FROM payloads WHERE id = ?", (payload_id,)).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(404, "Payload not found")
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if "category" in updates and updates["category"] not in VALID_CATEGORIES:
        conn.close()
        raise HTTPException(400, f"Invalid category. Must be one of: {VALID_CATEGORIES}")
    if updates:
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        conn.execute(
            f"UPDATE payloads SET {set_clause} WHERE id = ?",
            (*updates.values(), payload_id),
        )
        conn.commit()
    row = conn.execute("SELECT * FROM payloads WHERE id = ?", (payload_id,)).fetchone()
    conn.close()
    return dict(row)


@app.delete("/api/payloads/{payload_id}")
def delete_payload(payload_id: int):
    conn = get_db()
    conn.execute("DELETE FROM payloads WHERE id = ?", (payload_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


# -- Results ---------------------------------------------------------------

@app.get("/api/results")
def list_results(device_name: Optional[str] = Query(None)):
    conn = get_db()
    if device_name:
        rows = conn.execute(
            """SELECT r.*, p.text as payload_text
               FROM results r JOIN payloads p ON r.payload_id = p.id
               WHERE r.device_name = ? ORDER BY r.tested_at DESC""",
            (device_name,),
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT r.*, p.text as payload_text
               FROM results r JOIN payloads p ON r.payload_id = p.id
               ORDER BY r.tested_at DESC"""
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/results", status_code=201)
def create_result(result: ResultCreate):
    if result.status not in VALID_STATUSES:
        raise HTTPException(400, f"Invalid status. Must be one of: {VALID_STATUSES}")
    conn = get_db()
    payload = conn.execute("SELECT * FROM payloads WHERE id = ?", (result.payload_id,)).fetchone()
    if not payload:
        conn.close()
        raise HTTPException(404, "Payload not found")
    cur = conn.execute(
        "INSERT INTO results (payload_id, device_name, device_mac, status, notes) VALUES (?, ?, ?, ?, ?)",
        (result.payload_id, result.device_name, result.device_mac, result.status, result.notes),
    )
    conn.commit()
    row = conn.execute(
        """SELECT r.*, p.text as payload_text
           FROM results r JOIN payloads p ON r.payload_id = p.id
           WHERE r.id = ?""",
        (cur.lastrowid,),
    ).fetchone()
    conn.close()
    return dict(row)


@app.get("/api/results/matrix")
def get_results_matrix():
    conn = get_db()
    rows = conn.execute(
        """SELECT r.device_name, r.payload_id, p.text as payload_text,
                  p.category, r.status, r.tested_at
           FROM results r JOIN payloads p ON r.payload_id = p.id
           ORDER BY r.tested_at DESC"""
    ).fetchall()
    conn.close()

    devices = sorted(set(r["device_name"] for r in rows))
    payloads_seen: dict = {}
    for r in rows:
        payloads_seen[r["payload_id"]] = {
            "id": r["payload_id"],
            "text": r["payload_text"],
            "category": r["category"],
        }

    matrix: dict = {}
    for r in rows:
        matrix.setdefault(r["device_name"], {})[r["payload_id"]] = {
            "status": r["status"],
            "tested_at": r["tested_at"],
        }

    return {"devices": devices, "payloads": list(payloads_seen.values()), "matrix": matrix}


# -- Serial ----------------------------------------------------------------

@app.get("/api/serial/ports")
def list_serial_ports():
    return serial_manager.list_ports()


@app.post("/api/serial/connect")
async def connect_serial(req: SerialConnect):
    try:
        await serial_manager.connect(req.port, req.baud)
    except Exception as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True, "port": req.port}


@app.post("/api/serial/disconnect")
async def disconnect_serial():
    await serial_manager.stop()
    return {"ok": True}


@app.get("/api/serial/status")
def serial_status():
    connected = serial_manager.serial_conn is not None and serial_manager.serial_conn.is_open
    return {"connected": connected, "port": serial_manager.port if connected else None}


# -- Deploy ----------------------------------------------------------------

@app.post("/api/deploy")
async def deploy_payloads(req: DeployRequest):
    if not req.payload_ids:
        raise HTTPException(400, "No payload IDs provided")
    conn = get_db()
    placeholders = ",".join("?" for _ in req.payload_ids)
    rows = conn.execute(
        f"SELECT id, text FROM payloads WHERE id IN ({placeholders})",
        req.payload_ids,
    ).fetchall()
    conn.close()
    if not rows:
        raise HTTPException(404, "No payloads found for given IDs")
    texts = [r["text"] for r in rows]
    result = await serial_manager.push_payloads(texts)
    if not result["ok"]:
        raise HTTPException(400, result.get("error", "Deploy failed"))
    return {"ok": True, "count": result["count"], "status": "broadcasting"}


@app.post("/api/deploy/stop")
async def stop_deploy():
    await serial_manager.stop_esp()
    return {"ok": True, "status": "stopped"}


@app.get("/api/deploy/status")
def deploy_status():
    connected = serial_manager.serial_conn is not None and serial_manager.serial_conn.is_open
    return {
        "connected": connected,
        "deploy_status": serial_manager.deploy_status,
        "deploy_count": serial_manager.deploy_count,
    }


@app.post("/api/firmware/flash")
async def flash_firmware(req: FlashRequest):
    if not req.port:
        raise HTTPException(400, "No port specified")
    valid_boards = ("esp32", "esp8266")
    if req.board not in valid_boards:
        raise HTTPException(400, f"Invalid board. Must be one of: {valid_boards}")
    result = await serial_manager.flash_firmware(req.port, req.board)
    if not result["ok"]:
        raise HTTPException(400, result.get("error", "Flash failed"))
    return {"ok": True}


@app.websocket("/ws/serial")
async def ws_serial(ws: WebSocket):
    await ws.accept()
    serial_manager.register(ws)
    try:
        while True:
            data = await ws.receive_text()
            serial_manager.write(data)
    except WebSocketDisconnect:
        pass
    finally:
        serial_manager.unregister(ws)
