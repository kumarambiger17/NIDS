import os
import pandas as pd
from sklearn.preprocessing import LabelEncoder

# Get project root directory
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Dataset path
file_path = os.path.join(base_dir, "dataset", "Benign-Monday-no-metadata.parquet")

# Load dataset
df = pd.read_parquet(file_path)

print("Original Dataset Shape:", df.shape)

# Remove duplicate rows
df = df.drop_duplicates()

# Remove rows with missing values
df = df.dropna()

print("After Cleaning:", df.shape)

# Display column names
print("\nColumns:")
print(df.columns.tolist())

# Save cleaned dataset
output_path = os.path.join(base_dir, "dataset", "cleaned_dataset.parquet")
df.to_parquet(output_path, index=False)

print("\n✅ Cleaned dataset saved successfully!")