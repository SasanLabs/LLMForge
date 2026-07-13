import src.controllers.rag_data_exposure_controller  # noqa: F401  (registra o controller)
from src.framework.decorators import Variant, get_registry


def test_level4_endpoint_registered_as_secure():
    controller = next(
        c for c in get_registry() if c.name == "rag_sensitive_data_exposure"
    )
    endpoint = next(e for e in controller.endpoints if e.level == "level_4")
    assert endpoint.variant is Variant.SECURE
    assert endpoint.secret_token is None
