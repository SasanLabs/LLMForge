import os
import tempfile
from pathlib import Path

# Isolates the lab's vector store in a temporary directory. Must run BEFORE
# any test imports the lab module (the path is read at import time).
_TEST_VECTOR_DIR = Path(tempfile.gettempdir()) / "llmforge_test_rag_data_exposure"
os.environ.setdefault("RAG_DATA_EXPOSURE_VECTOR_DIR", str(_TEST_VECTOR_DIR))
