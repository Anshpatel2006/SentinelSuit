from fastapi import APIRouter

from api.routes.dashboard import router as dashboard_router

router = APIRouter()

# ============================================================
# REGISTER ROUTES
# ============================================================

router.include_router(dashboard_router)
