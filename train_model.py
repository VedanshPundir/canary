
import json
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Load dataset
file_list = [
    "large_honeypot_5000.json",
    # Add other datasets here if needed
]

dfs = []
for file in file_list:
    df_temp = pd.read_json(file)
    dfs.append(df_temp)
df = pd.concat(dfs, ignore_index=True)

# Preprocessing
df['timestamp'] = pd.to_datetime(df['timestamp'])
df['hour'] = df['timestamp'].dt.hour
df['dayofweek'] = df['timestamp'].dt.dayofweek

# Combine username and password into a single text feature
df['combined_text'] = df['username'].astype(str) + " " + df['password'].astype(str)

# Define features and target
X = df[['combined_text', 'user_agent', 'hour', 'dayofweek']]
y = df['login_success']

# Preprocessing and feature extraction pipeline
preprocessor = ColumnTransformer(
    transformers=[
        ('text', TfidfVectorizer(), 'combined_text'),
        ('user_agent', OneHotEncoder(handle_unknown='ignore'), ['user_agent']),
        # 'hour' and 'dayofweek' are numeric, pass them through as is
    ],
    remainder='passthrough'  # pass hour and dayofweek without change
)

# Create the pipeline with preprocessor and classifier
pipeline = Pipeline([
    ('preprocessor', preprocessor),
    ('classifier', LogisticRegression(max_iter=1000))
])

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
pipeline.fit(X_train, y_train)

# Predict and evaluate
y_pred = pipeline.predict(X_test)
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Save model pipeline for later use
joblib.dump(pipeline, 'login_pipeline_model.pkl')
print("\n✅ Model pipeline saved successfully!")
