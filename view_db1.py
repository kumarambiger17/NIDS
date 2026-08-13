import sqlite3

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Show all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

print("Tables:", tables)

# Display data from each table
for table in tables:
    table_name = table[0]
    print(f"\n--- {table_name} ---")

    cursor.execute(f"SELECT * FROM {table_name}")
    rows = cursor.fetchall()

    for row in rows:
        print(row)

conn.close()
