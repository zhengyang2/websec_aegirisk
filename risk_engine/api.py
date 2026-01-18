from fastapi import FastAPI

# db import
from risk_engine.db.db_setup import Base, engine

#routes imports
from risk_engine.routes.cookie_route import cookie_router

#component import





app = FastAPI(title="RBA Risk Engine")
app.include_router(cookie_router)




@app.on_event("startup")
def init_db():
    Base.metadata.create_all(bind=engine)



@app.get("/")
def read_root():

    return {"Hello": "World"}




