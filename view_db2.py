import sqlite3
import os

APP_DATA = os.path.join(os.getenv("LOCALAPPDATA"), "AI_NIDS")
DB_PATH = os.path.join(APP_DATA, "users.db")

print("Database:", DB_PATH)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Show all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

print("\nTables:", tables)

for table in tables:
    table_name = table[0]
    print(f"\n===== {table_name} =====")

    # Show column names
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [col[1] for col in cursor.fetchall()]
    print("Columns:", columns)

    # Show data
    cursor.execute(f"SELECT * FROM {table_name}")
    rows = cursor.fetchall()

    if rows:
        for row in rows:
            print(row)
    else:
        print("No data found.")

conn.close()