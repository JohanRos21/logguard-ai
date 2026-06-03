import os
from contextlib import contextmanager

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker


load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://logguard_user:logguard_password@127.0.0.1:5433/logguard_ai"
)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db():
    """
    Dependencia para FastAPI.
    Abre una sesión por request y la cierra al terminar.
    """
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_session():
    """
    Context manager para scripts.
    Lo usaremos en servicios como database_seed_service.py.
    """
    db = SessionLocal()

    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def test_connection():
    """
    Prueba mínima para confirmar que Python puede conectarse a PostgreSQL.
    """
    with engine.connect() as connection:
        result = connection.execute(text("SELECT 1"))
        return result.scalar()


def create_database_tables():
    """
    Importamos los modelos antes de crear tablas.
    SQLAlchemy necesita que las clases estén cargadas en Base.metadata.
    """
    from backend.app import database as database_module
    import backend.app.db_models  # noqa: F401

    database_module.Base.metadata.create_all(bind=database_module.engine)


def main():
    print("Probando conexión con PostgreSQL...")

    result = test_connection()

    if result == 1:
        print("Conexión exitosa con PostgreSQL.")

    print("Creando tablas de LogGuard AI V3...")
    create_database_tables()
    print("Tablas creadas correctamente.")


if __name__ == "__main__":
    main()
