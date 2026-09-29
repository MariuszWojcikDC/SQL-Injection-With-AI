from dataclasses import dataclass
from urllib.parse import quote_plus


@dataclass(frozen=True)
class DatabaseConfig:
    driver: str = "ODBC Driver 18 for SQL Server"
    server: str = "localhost"
    database: str = "AdventureWorks2025"
    trusted_connection: str = "yes"
    encrypt: str = "no"
    trust_server_certificate: str = "yes"

    def to_sqlalchemy_url(self) -> str:
        odbc_connection = (
            f"DRIVER={{{self.driver}}};"
            f"SERVER={self.server};"
            f"DATABASE={self.database};"
            f"Trusted_Connection={self.trusted_connection};"
            f"Encrypt={self.encrypt};"
            f"TrustServerCertificate={self.trust_server_certificate};"
        )
        return f"mssql+pyodbc:///?odbc_connect={quote_plus(odbc_connection)}"


DATABASE_CONFIG = DatabaseConfig()
