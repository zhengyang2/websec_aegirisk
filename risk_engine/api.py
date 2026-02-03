from fastapi import FastAPI

# db import
from risk_engine.db.db_setup import Base, engine

# ensure models are registered with Base before create_all
from risk_engine.db import cookie_model
from risk_engine.db import risk_model

#routes imports
from risk_engine.routes.cookie_route import cookie_router
from risk_engine.routes.risk_route import risk_router
from risk_engine.routes.dashboard_route import dashboard_router

#component import

app = FastAPI(title="RBA Risk Engine")
app.include_router(cookie_router)
app.include_router(risk_router)
app.include_router(dashboard_router)

@app.on_event("startup")
def init_db():
    Base.metadata.create_all(bind=engine)

@app.get("/")
def read_root():

    return {"Hello": "World"}