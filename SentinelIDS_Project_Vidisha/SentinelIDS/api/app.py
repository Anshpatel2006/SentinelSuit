from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router

app = FastAPI(
    title="SentinelIDS API",
    version="1.0.0",
    description="AI-Powered Hybrid Intrusion Detection System Backend"
)

# ============================================================
# CORS CONFIGURATION
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# REGISTER ALL ROUTES
# ============================================================

app.include_router(router)

# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():
    return {
        "application": "SentinelIDS",
        "version": "1.0.0",
        "status": "Running"
    }


@app.get("/health")
def health_check():
    return {
        "application": "SentinelIDS",
        "status": "Healthy",
        "version": "1.0.0"
    }
