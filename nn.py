import pandas as pd

# Path to the dataset
file_path = "dataset/Benign-Monday-no-metadata.parquet"

# Read the Parquet file
df = pd.read_parquet(file_path)

# Display dataset information
print("=" * 50)
print("First 5 Rows:")
print(df.head())

print("\n" + "=" * 50)
print("Dataset Shape:")
print(df.shape)

print("\n" + "=" * 50)
print("Column Names:")
print(df.columns.tolist())

print("\n" + "=" * 50)
print("Data Types:")
print(df.dtypes)

print("\n" + "=" * 50)
print("Missing Values:")
print(df.isnull().sum())