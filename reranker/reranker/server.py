import os, argparse
from typing import List
from fastapi import FastAPI
from pydantic import BaseModel
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_DIR = os.environ.get(
    "MEDCPT_MODEL_DIR",
    os.path.join(os.path.dirname(__file__), "..", "model")
)

tok = AutoTokenizer.from_pretrained(MODEL_DIR, local_files_only=True)
mdl = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR, local_files_only=True)
mdl.eval()

app = FastAPI()

class RerankRequest(BaseModel):
    query: str
    candidates: List[str]
    top_k: int = 5

@app.post("/rerank")
def rerank(req: RerankRequest):
    pairs = [[req.query, c] for c in req.candidates]
    with torch.no_grad():
        enc = tok(pairs, truncation=True, padding=True, return_tensors="pt", max_length=512)
        scores = mdl(**enc).logits.squeeze(dim=1).tolist()
    order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:req.top_k]
    return {"indices": order, "scores": [scores[i] for i in order]}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=args.port)
