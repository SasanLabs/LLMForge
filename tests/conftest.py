import os
import tempfile
from pathlib import Path

# Isola o vector store do lab em um diretório temporário. Precisa rodar ANTES de
# qualquer teste importar o módulo do lab (o caminho é lido no import).
_TEST_VECTOR_DIR = Path(tempfile.gettempdir()) / "llmforge_test_rag_data_exposure"
os.environ.setdefault("RAG_DATA_EXPOSURE_VECTOR_DIR", str(_TEST_VECTOR_DIR))
