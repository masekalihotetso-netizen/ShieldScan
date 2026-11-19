"""Train / retrain the phishing text model.  Usage:
    python -m shieldscan.train_text                    # seed corpus
    python -m shieldscan.train_text --csv data.csv     # your own dataset (text,label)
"""
import argparse
import csv
import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline, FeatureUnion

from . import data

MODEL_PATH = os.path.join(os.path.dirname(__file__), "text_model.joblib")


def make_pipeline():
    feats = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, lowercase=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True)),
    ])
    return Pipeline([("f", feats), ("clf", LogisticRegression(C=4.0, max_iter=2000, class_weight="balanced"))])


def retrain_seed():
    """Rebuild the bundled model from the seed corpus (used automatically if the saved one is unreadable)."""
    X, y = data.build()
    p = make_pipeline().fit(X, y)
    try:
        joblib.dump(p, MODEL_PATH)
    except OSError:
        pass                                  # read-only install: keep the in-memory model
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv")
    a = ap.parse_args()
    if a.csv:
        X, y = [], []
        with open(a.csv, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                X.append(r["text"]); y.append(int(r["label"]))
    else:
        X, y = data.build()
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=1, stratify=y)
    p = make_pipeline().fit(Xtr, ytr)
    print(classification_report(yte, p.predict(Xte), digits=3))
    p.fit(X, y)
    joblib.dump(p, MODEL_PATH)
    print("saved", MODEL_PATH)


if __name__ == "__main__":
    main()
