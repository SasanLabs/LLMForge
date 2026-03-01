from fastapi import FastAPI

from . import vulnerable_app as vapp
from .controllers.command_injection_controller import router as command_injection_router
from .controllers.deserialization_controller import router as deserialization_router
from .controllers.meta_controller import router as meta_router
from .controllers.path_traversal_controller import router as path_traversal_router
from .controllers.sql_injection_controller import router as sql_injection_router
from .controllers.xss_controller import router as xss_router

app = FastAPI(title="LLMForge Gateway")

# Initialize the local vuln DB
vapp.init_db()

app.include_router(sql_injection_router)
app.include_router(xss_router)
app.include_router(command_injection_router)
app.include_router(path_traversal_router)
app.include_router(deserialization_router)
app.include_router(meta_router)
