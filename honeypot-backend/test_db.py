from sqlalchemy import text
from database import engine

with engine.connect() as connection:
    result = connection.execute(
        text("SELECT current_database(), current_user")
    ).one()

    print("Database:", result[0])
    print("User:", result[1])
    print("PostgreSQL connection successful.")