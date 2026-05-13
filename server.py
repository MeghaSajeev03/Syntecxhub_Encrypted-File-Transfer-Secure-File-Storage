import os
import uuid
import json
from fastapi import FastAPI, UploadFile, Request, HTTPException, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI(title="Secure File Transfer Server")
STORAGE_DIR = "storage"
os.makedirs(STORAGE_DIR, exist_ok=True)

class InitUploadRequest(BaseModel):
    filename: str
    total_size: int

class InitUploadResponse(BaseModel):
    file_id: str

class FinishUploadRequest(BaseModel):
    hmac_sha256: str

@app.post("/init", response_model=InitUploadResponse)
def init_upload(req: InitUploadRequest):
    file_id = str(uuid.uuid4())
    metadata_path = os.path.join(STORAGE_DIR, f"{file_id}.json")
    with open(metadata_path, "w") as f:
        json.dump({"filename": req.filename, "total_size": req.total_size, "status": "uploading"}, f)
    # create empty data file
    data_path = os.path.join(STORAGE_DIR, f"{file_id}.dat")
    with open(data_path, "wb") as f:
        pass
    return {"file_id": file_id}

@app.put("/upload/{file_id}")
async def upload_chunk(file_id: str, offset: int, request: Request):
    metadata_path = os.path.join(STORAGE_DIR, f"{file_id}.json")
    if not os.path.exists(metadata_path):
        raise HTTPException(status_code=404, detail="Upload ID not found")
        
    data_path = os.path.join(STORAGE_DIR, f"{file_id}.dat")
    chunk_data = await request.body()
    
    with open(data_path, "r+b") as f:
        f.seek(offset)
        f.write(chunk_data)
        
    return {"status": "chunk received"}

@app.post("/finish/{file_id}")
def finish_upload(file_id: str, req: FinishUploadRequest):
    metadata_path = os.path.join(STORAGE_DIR, f"{file_id}.json")
    if not os.path.exists(metadata_path):
        raise HTTPException(status_code=404, detail="Upload ID not found")
        
    with open(metadata_path, "r") as f:
        meta = json.load(f)
        
    meta["status"] = "finished"
    meta["hmac_sha256"] = req.hmac_sha256
    
    with open(metadata_path, "w") as f:
        json.dump(meta, f)
        
    return {"status": "completed"}

@app.get("/metadata/{file_id}")
def get_metadata(file_id: str):
    metadata_path = os.path.join(STORAGE_DIR, f"{file_id}.json")
    if not os.path.exists(metadata_path):
        raise HTTPException(status_code=404, detail="File metadata not found")
    with open(metadata_path, "r") as f:
        return json.load(f)

@app.get("/download/{file_id}")
def download_file(file_id: str):
    data_path = os.path.join(STORAGE_DIR, f"{file_id}.dat")
    if not os.path.exists(data_path):
        raise HTTPException(status_code=404, detail="File data not found")
    
    return FileResponse(data_path, media_type='application/octet-stream', filename=f"{file_id}.dat")
