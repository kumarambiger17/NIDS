import os
import pandas as pd

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
dataset_dir = os.path.join(base_dir, "dataset")

files = [
    "Benign-Monday-no-metadata.parquet",
    "Botnet-Friday-no-metadata.parquet",
    "Bruteforce-Tuesday-no-metadata.parquet",
    "DDoS-Friday-no-metadata.parquet",
    "DoS-Wednesday-no-metadata.parquet",
    "Infiltration-Thursday-no-metadata.parquet",
    "Portscan-Friday-no-metadata.parquet",
    "WebAttacks-Thursday-no-metadata.parquet"
]

dataframes = []

for file in files:
    path = os.path.join(dataset_dir, file)
    df = pd.read_parquet(path)
    print(f"Loaded {file}: {df.shape}")
    dataframes.append(df)

merged_df = pd.concat(dataframes, ignore_index=True)

print("\nMerged Dataset Shape:", merged_df.shape)

output_file = os.path.join(dataset_dir, "merged_dataset.parquet")
merged_df.to_parquet(output_file, index=False)

print("\n✅ merged_dataset.parquet created successfully!")