from .app_factory import create_app
from .repositories import ProductRepository, ProductRepositoryVulnerable


def create_default_app():
    secure_repository = ProductRepository()
    vulnerable_repository = ProductRepositoryVulnerable()
    secure_repository.ensure_lab_assets()
    vulnerable_repository.ensure_lab_assets()

    return create_app(
        secure_repository=secure_repository,
        vulnerable_repository=vulnerable_repository,
    )


__all__ = [
    "create_app",
    "create_default_app",
    "ProductRepository",
    "ProductRepositoryVulnerable",
]
