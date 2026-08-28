from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from backend.app.database import engine, Base
from backend.app.api import routes_health, routes_scan, routes_findings, routes_history, routes_validation

# Initialize DB tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SecretTrace AI API",
    description="AI-powered secret detection, validation, and Git-history provenance platform API",
    version="1.0.0"
)

# Configure CORS for local frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all origins in local hackathon / dev environments
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(routes_health.router)
app.include_router(routes_scan.router)
app.include_router(routes_findings.router)
app.include_router(routes_history.router)
app.include_router(routes_validation.router)

@app.get("/")
def read_root():
    return {
        "message": "Welcome to SecretTrace AI API",
        "docs_url": "/docs",
        "health_url": "/api/health"
    }

if __name__ == "__main__":
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
