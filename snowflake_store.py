
import os
import snowflake.connector
from dotenv import load_dotenv

load_dotenv()


def get_connection():
    """Connect to Snowflake using credentials stored in .env."""
    required = [
        "SNOWFLAKE_ACCOUNT",
        "SNOWFLAKE_USER",
        "SNOWFLAKE_PASSWORD",
        "SNOWFLAKE_WAREHOUSE",
        "SNOWFLAKE_DATABASE",
        "SNOWFLAKE_SCHEMA",
    ]

    missing = [name for name in required if not os.getenv(name)]

    if missing:
        raise ValueError(
            "Missing Snowflake settings in .env: "
            + ", ".join(missing)
        )

    return snowflake.connector.connect(
        account=os.getenv("SNOWFLAKE_ACCOUNT"),
        user=os.getenv("SNOWFLAKE_USER"),
        password=os.getenv("SNOWFLAKE_PASSWORD"),
        warehouse=os.getenv("SNOWFLAKE_WAREHOUSE"),
        database=os.getenv("SNOWFLAKE_DATABASE"),
        schema=os.getenv("SNOWFLAKE_SCHEMA"),
    )


def test_connection():
    """Check whether Snowflake accepts the connection."""
    connection = get_connection()

    try:
        cursor = connection.cursor()
        try:
            cursor.execute("SELECT CURRENT_VERSION()")
            result = cursor.fetchone()
            print("Snowflake connection successful!")
            print("Snowflake version:", result[0])
        finally:
            cursor.close()
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        test_connection()
    except Exception as error:
        print("Snowflake connection failed:", error)
