import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
import pickle

def preprocess_data(input_file, output_file):
    # Load the CSV file
    data = pd.read_csv(input_file)

    # Ensure the dataset has 'text' and 'label' columns
    if 'text' not in data.columns or 'label' not in data.columns:
        raise ValueError("Input CSV must have 'text' and 'label' columns.")

    # Vectorize the text using TF-IDF
    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(data['text']).toarray()

    # Extract labels
    y = data['label'].values

    # Save preprocessed data and vectorizer
    with open(output_file, "wb") as f:
        pickle.dump((X, y, vectorizer), f)

    print(f"Preprocessed data saved to {output_file}")

if __name__ == "__main__":
    preprocess_data("data/phishing_emails.csv", "data/preprocessed_data.pkl")
