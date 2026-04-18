from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model.explain import SecurifyModel

app = FastAPI(
    description="Real-world ML Intrusion Detection integration with SHAP explainability.",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    print("Loading 26-feature RF model and offline dataset into memory...")
    SecurifyModel.load()
    print("Initialization complete!")

@app.get("/simulate/attack")
def simulate_attack(type: str = "normal"):
    """
    Endpoint called from the React Frontend.
    Takes a string ?type= (e.g. 'ddos', 'botnet', 'http')
    And returns the SHAP predictions for it.
    """
    try:
        result = SecurifyModel.get_simulation(type)
        return result
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
