<!-- Source: https://wazuh.com/blog/monitoring-snowflake-data-warehouse-with-wazuh/ | Article: Monitoring Snowflake data warehouse with Wazuh -->
import os
import logging
import snowflake.connector
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

# === Setup logging ===
logging.basicConfig(
    filename="/etc/snowflake_logs/script.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# === Snowflake connection details (use env vars for security) ===
SNOWFLAKE_USER = os.getenv("SNOWFLAKE_USER")
SNOWFLAKE_PASSWORD = os.getenv("SNOWFLAKE_PASSWORD")
SNOWFLAKE_ACCOUNT = os.getenv("SNOWFLAKE_ACCOUNT")
SNOWFLAKE_WAREHOUSE = os.getenv("SNOWFLAKE_WAREHOUSE")
SNOWFLAKE_DATABASE = os.getenv("SNOWFLAKE_DATABASE")
SNOWFLAKE_SCHEMA = os.getenv("SNOWFLAKE_SCHEMA")

# === Paths ===
QUERY_DIR = "/etc/snowflake_logs/queries"
OUTPUT_DIR = "/etc/snowflake_logs/logs"
STATE_DIR = "/etc/snowflake_logs/state"

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(STATE_DIR, exist_ok=True)

# === Connect to Snowflake ===
try:
    conn = snowflake.connector.connect(
        user=SNOWFLAKE_USER,
        password=SNOWFLAKE_PASSWORD,
        account=SNOWFLAKE_ACCOUNT,
        warehouse=SNOWFLAKE_WAREHOUSE,
        database=SNOWFLAKE_DATABASE,
        schema=SNOWFLAKE_SCHEMA,
    )
    cursor = conn.cursor()
except Exception as e:
    logging.error(f"Failed to connect to Snowflake: {e}")
    raise


def get_last_value(state_file):
    """Read last processed ID/timestamp from state file."""
    if os.path.exists(state_file):
        with open(state_file, "r") as f:
            return f.read().strip()
    return None


def save_last_value(state_file, value):
    """Save last processed ID/timestamp to state file."""
    with open(state_file, "w") as f:
        f.write(str(value))


# === Loop through SQL files ===
for filename in os.listdir(QUERY_DIR):
    if filename.endswith(".sql"):
        query_path = os.path.join(QUERY_DIR, filename)
        output_file = os.path.join(OUTPUT_DIR, f"{os.path.splitext(filename)[0]}.json")
        state_file = os.path.join(STATE_DIR, f"{os.path.splitext(filename)[0]}.state")

        try:
            with open(query_path, "r") as f:
                base_query = f.read().strip()

            last_value = get_last_value(state_file)
            if last_value:
                # Assumption: query has a placeholder like {{last_value}}
                query = base_query.replace("{{last_value}}", last_value)
            else:
                query = base_query.replace("{{last_value}}", "0")  # default start

            logging.info(f"Running query from {filename} with last_value={last_value or 0}")
            cursor.execute(query)

            df = cursor.fetch_pandas_all()

            if not df.empty:
                # Append as NDJSON
                df.to_json(output_file, orient="records", lines=True, mode="a")

                # Update state with the max EVENT_ID or TIMESTAMP
                if "EVENT_ID" in df.columns:
                    new_last = df["EVENT_ID"].max()
                elif "TIMESTAMP" in df.columns:
                    new_last = df["TIMESTAMP"].max()
                elif "END_TIME" in df.columns:
                    new_last = df["END_TIME"].max()
                else:
                    raise ValueError("No EVENT_ID or TIMESTAMP column found for tracking")

                save_last_value(state_file, new_last)
                logging.info(f"Appended {len(df)} rows to {output_file}, new last_value={new_last}")
            else:
                logging.info(f"No new rows for {filename}")

        except Exception as e:
            logging.error(f"Error processing {filename}: {e}")

# === Cleanup ===
cursor.close()
conn.close()