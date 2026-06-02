import os
import json
import random
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from torch.utils.data import Dataset, DataLoader


INPUT_PATH = "data/processed/log_sequences.csv"

MODEL_DIR = "models/sequence_transformer"
MODEL_PATH = os.path.join(MODEL_DIR, "sequence_transformer.pt")
VOCAB_PATH = os.path.join(MODEL_DIR, "vocab.json")
CONFIG_PATH = os.path.join(MODEL_DIR, "config.json")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")

REPORT_PATH = "reports/sequence_transformer_report.json"
PREDICTIONS_PATH = "reports/sequence_transformer_predictions.csv"


RANDOM_SEED = 42

MAX_LEN = 20
BATCH_SIZE = 32
EPOCHS = 15
LEARNING_RATE = 1e-3

EMBEDDING_DIM = 64
NUM_HEADS = 4
NUM_LAYERS = 2
FF_DIM = 128
DROPOUT = 0.2

CLASS_NAMES = ["normal", "anomaly"]


def set_seed(seed: int = RANDOM_SEED):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)

    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def load_sequences(input_path=INPUT_PATH):
    if not os.path.exists(input_path):
        raise FileNotFoundError(
            f"No se encontró {input_path}. Primero ejecuta sequence_builder_service.py"
        )

    df = pd.read_csv(input_path, encoding="utf-8-sig")

    required_columns = [
        "sequence_id",
        "event_sequence",
        "route_sequence",
        "status_sequence",
        "method_sequence",
        "label",
        "label_id",
    ]

    missing_columns = [
        column for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(f"Faltan columnas necesarias para entrenar el Transformer: {missing_columns}")

    df = df.dropna(subset=[
        "event_sequence",
        "route_sequence",
        "status_sequence",
        "method_sequence",
        "label_id",
    ])

    df["label_id"] = df["label_id"].astype(int)

    return df


def split_tokens(sequence_text: str) -> List[str]:
    return str(sequence_text).split()


def build_vocab(sequences: List[str]) -> Dict[str, int]:
    """
    Cada tipo de secuencia tiene su propio vocabulario.

    Ejemplo:
    event_sequence:
    login_failed payment_failed server_error

    route_sequence:
    /login /api/payments /api/reports

    No usamos BERT porque estos tokens ya son eventos estructurados,
    no lenguaje natural.
    """

    vocab = {
        "<PAD>": 0,
        "<UNK>": 1,
    }

    for sequence in sequences:
        for token in split_tokens(sequence):
            if token not in vocab:
                vocab[token] = len(vocab)

    return vocab


def encode_sequence(sequence_text: str, vocab: Dict[str, int], max_len: int = MAX_LEN) -> List[int]:
    tokens = split_tokens(sequence_text)

    encoded = [
        vocab.get(token, vocab["<UNK>"])
        for token in tokens[:max_len]
    ]

    if len(encoded) < max_len:
        encoded += [vocab["<PAD>"]] * (max_len - len(encoded))

    return encoded


def build_all_vocabs(df: pd.DataFrame):
    vocabs = {
        "event_vocab": build_vocab(df["event_sequence"].tolist()),
        "route_vocab": build_vocab(df["route_sequence"].tolist()),
        "status_vocab": build_vocab(df["status_sequence"].astype(str).tolist()),
        "method_vocab": build_vocab(df["method_sequence"].tolist()),
    }

    return vocabs


class LogSequenceDataset(Dataset):
    def __init__(self, df: pd.DataFrame, vocabs: Dict[str, Dict[str, int]]):
        self.df = df.reset_index(drop=True)
        self.vocabs = vocabs

    def __len__(self):
        return len(self.df)

    def __getitem__(self, index):
        row = self.df.iloc[index]

        event_ids = encode_sequence(row["event_sequence"], self.vocabs["event_vocab"])
        route_ids = encode_sequence(row["route_sequence"], self.vocabs["route_vocab"])
        status_ids = encode_sequence(str(row["status_sequence"]), self.vocabs["status_vocab"])
        method_ids = encode_sequence(row["method_sequence"], self.vocabs["method_vocab"])

        label = int(row["label_id"])

        return {
            "event_ids": torch.tensor(event_ids, dtype=torch.long),
            "route_ids": torch.tensor(route_ids, dtype=torch.long),
            "status_ids": torch.tensor(status_ids, dtype=torch.long),
            "method_ids": torch.tensor(method_ids, dtype=torch.long),
            "label": torch.tensor(label, dtype=torch.long),
        }


class LogSequenceTransformer(nn.Module):
    def __init__(
        self,
        event_vocab_size: int,
        route_vocab_size: int,
        status_vocab_size: int,
        method_vocab_size: int,
        max_len: int,
        embedding_dim: int,
        num_heads: int,
        num_layers: int,
        ff_dim: int,
        dropout: float,
        num_classes: int = 2,
    ):
        super().__init__()

        self.event_embedding = nn.Embedding(event_vocab_size, embedding_dim, padding_idx=0)
        self.route_embedding = nn.Embedding(route_vocab_size, embedding_dim, padding_idx=0)
        self.status_embedding = nn.Embedding(status_vocab_size, embedding_dim, padding_idx=0)
        self.method_embedding = nn.Embedding(method_vocab_size, embedding_dim, padding_idx=0)

        # El positional embedding permite que el Transformer sepa el orden de los eventos.
        # Sin esto, vería los tokens como una bolsa sin posición temporal.
        self.position_embedding = nn.Embedding(max_len, embedding_dim)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embedding_dim,
            nhead=num_heads,
            dim_feedforward=ff_dim,
            dropout=dropout,
            batch_first=True,
        )

        self.transformer_encoder = nn.TransformerEncoder(
            encoder_layer,
            num_layers=num_layers,
        )

        self.dropout = nn.Dropout(dropout)
        self.classifier = nn.Sequential(
            nn.Linear(embedding_dim, ff_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(ff_dim, num_classes),
        )

    def forward(self, event_ids, route_ids, status_ids, method_ids):
        batch_size, sequence_length = event_ids.shape

        positions = torch.arange(
            0,
            sequence_length,
            device=event_ids.device,
        ).unsqueeze(0).expand(batch_size, sequence_length)

        # Combinamos varias señales por posición:
        # evento + ruta + status + método + posición.
        # Así el modelo no solo ve "payment_failed", también ve dónde ocurrió
        # y con qué código HTTP.
        x = (
            self.event_embedding(event_ids)
            + self.route_embedding(route_ids)
            + self.status_embedding(status_ids)
            + self.method_embedding(method_ids)
            + self.position_embedding(positions)
        )

        padding_mask = event_ids.eq(0)

        x = self.transformer_encoder(
            x,
            src_key_padding_mask=padding_mask,
        )

        # Pooling enmascarado:
        # resumimos la secuencia ignorando posiciones PAD.
        valid_mask = (~padding_mask).unsqueeze(-1).float()
        x = x * valid_mask

        summed = x.sum(dim=1)
        counts = valid_mask.sum(dim=1).clamp(min=1.0)
        pooled = summed / counts

        pooled = self.dropout(pooled)
        logits = self.classifier(pooled)

        return logits


def calculate_class_weights(y_train: np.ndarray, device):
    """
    Aunque el dataset quedó casi balanceado, usamos class weights para evitar
    que el modelo favorezca una clase si hay pequeñas diferencias.
    """

    class_counts = np.bincount(y_train, minlength=2)
    total = class_counts.sum()

    weights = total / (len(class_counts) * class_counts)
    weights = torch.tensor(weights, dtype=torch.float32).to(device)

    return weights


def train_one_epoch(model, dataloader, optimizer, criterion, device):
    model.train()

    total_loss = 0.0

    for batch in dataloader:
        event_ids = batch["event_ids"].to(device)
        route_ids = batch["route_ids"].to(device)
        status_ids = batch["status_ids"].to(device)
        method_ids = batch["method_ids"].to(device)
        labels = batch["label"].to(device)

        optimizer.zero_grad()

        logits = model(event_ids, route_ids, status_ids, method_ids)
        loss = criterion(logits, labels)

        loss.backward()
        optimizer.step()

        total_loss += loss.item()

    return total_loss / len(dataloader)


def evaluate_model(model, dataloader, criterion, device):
    model.eval()

    total_loss = 0.0
    all_labels = []
    all_predictions = []
    all_probabilities = []

    with torch.no_grad():
        for batch in dataloader:
            event_ids = batch["event_ids"].to(device)
            route_ids = batch["route_ids"].to(device)
            status_ids = batch["status_ids"].to(device)
            method_ids = batch["method_ids"].to(device)
            labels = batch["label"].to(device)

            logits = model(event_ids, route_ids, status_ids, method_ids)
            loss = criterion(logits, labels)

            probabilities = torch.softmax(logits, dim=1)
            predictions = torch.argmax(probabilities, dim=1)

            total_loss += loss.item()

            all_labels.extend(labels.cpu().numpy().tolist())
            all_predictions.extend(predictions.cpu().numpy().tolist())
            all_probabilities.extend(probabilities[:, 1].cpu().numpy().tolist())

    avg_loss = total_loss / len(dataloader)

    return avg_loss, all_labels, all_predictions, all_probabilities


def build_metrics(y_true, y_pred, test_loss):
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    report = classification_report(
        y_true,
        y_pred,
        target_names=CLASS_NAMES,
        zero_division=0,
        output_dict=True,
    )

    matrix = confusion_matrix(y_true, y_pred).tolist()

    return {
        "model": "LogSequenceTransformer",
        "accuracy": float(accuracy),
        "precision_anomaly": float(precision),
        "recall_anomaly": float(recall),
        "f1_anomaly": float(f1),
        "loss": float(test_loss),
        "classification_report": report,
        "confusion_matrix": matrix,
        "classes": CLASS_NAMES,
        "max_len": MAX_LEN,
        "epochs": EPOCHS,
        "batch_size": BATCH_SIZE,
        "learning_rate": LEARNING_RATE,
        "embedding_dim": EMBEDDING_DIM,
        "num_heads": NUM_HEADS,
        "num_layers": NUM_LAYERS,
        "ff_dim": FF_DIM,
        "dropout": DROPOUT,
    }


def save_artifacts(model, vocabs, config, metrics, predictions_df):
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs("reports", exist_ok=True)

    torch.save(model.state_dict(), MODEL_PATH)

    with open(VOCAB_PATH, "w", encoding="utf-8") as file:
        json.dump(vocabs, file, indent=4, ensure_ascii=False)

    with open(CONFIG_PATH, "w", encoding="utf-8") as file:
        json.dump(config, file, indent=4, ensure_ascii=False)

    with open(METRICS_PATH, "w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=4, ensure_ascii=False)

    with open(REPORT_PATH, "w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=4, ensure_ascii=False)

    predictions_df.to_csv(PREDICTIONS_PATH, index=False, encoding="utf-8-sig")


def main():
    set_seed()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    print(f"Usando dispositivo: {device}")

    print("Cargando dataset secuencial...")
    df = load_sequences()

    print("Distribución de etiquetas:")
    print(df["label"].value_counts())

    train_df, test_df = train_test_split(
        df,
        test_size=0.2,
        random_state=RANDOM_SEED,
        stratify=df["label_id"],
    )

    vocabs = build_all_vocabs(train_df)

    train_dataset = LogSequenceDataset(train_df, vocabs)
    test_dataset = LogSequenceDataset(test_df, vocabs)

    train_loader = DataLoader(
        train_dataset,
        batch_size=BATCH_SIZE,
        shuffle=True,
    )

    test_loader = DataLoader(
        test_dataset,
        batch_size=BATCH_SIZE,
        shuffle=False,
    )

    model = LogSequenceTransformer(
        event_vocab_size=len(vocabs["event_vocab"]),
        route_vocab_size=len(vocabs["route_vocab"]),
        status_vocab_size=len(vocabs["status_vocab"]),
        method_vocab_size=len(vocabs["method_vocab"]),
        max_len=MAX_LEN,
        embedding_dim=EMBEDDING_DIM,
        num_heads=NUM_HEADS,
        num_layers=NUM_LAYERS,
        ff_dim=FF_DIM,
        dropout=DROPOUT,
        num_classes=len(CLASS_NAMES),
    ).to(device)

    class_weights = calculate_class_weights(
        y_train=train_df["label_id"].values,
        device=device,
    )

    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)

    best_f1 = -1.0
    best_state = None

    print("\nEntrenando Transformer secuencial...")

    for epoch in range(1, EPOCHS + 1):
        train_loss = train_one_epoch(
            model=model,
            dataloader=train_loader,
            optimizer=optimizer,
            criterion=criterion,
            device=device,
        )

        test_loss, y_true, y_pred, _ = evaluate_model(
            model=model,
            dataloader=test_loader,
            criterion=criterion,
            device=device,
        )

        current_f1 = f1_score(y_true, y_pred, zero_division=0)

        print(
            f"Epoch {epoch}/{EPOCHS} "
            f"- train_loss: {train_loss:.4f} "
            f"- test_loss: {test_loss:.4f} "
            f"- f1_anomaly: {current_f1:.4f}"
        )

        if current_f1 > best_f1:
            best_f1 = current_f1
            best_state = model.state_dict()

    if best_state is not None:
        model.load_state_dict(best_state)

    test_loss, y_true, y_pred, probabilities = evaluate_model(
        model=model,
        dataloader=test_loader,
        criterion=criterion,
        device=device,
    )

    metrics = build_metrics(
        y_true=y_true,
        y_pred=y_pred,
        test_loss=test_loss,
    )

    predictions_df = test_df.copy().reset_index(drop=True)
    predictions_df["predicted_label_id"] = y_pred
    predictions_df["predicted_label"] = [
        CLASS_NAMES[prediction]
        for prediction in y_pred
    ]
    predictions_df["anomaly_probability"] = probabilities

    config = {
        "model": "LogSequenceTransformer",
        "max_len": MAX_LEN,
        "embedding_dim": EMBEDDING_DIM,
        "num_heads": NUM_HEADS,
        "num_layers": NUM_LAYERS,
        "ff_dim": FF_DIM,
        "dropout": DROPOUT,
        "class_names": CLASS_NAMES,
        "feature_sources": [
            "event_sequence",
            "route_sequence",
            "status_sequence",
            "method_sequence",
        ],
    }

    save_artifacts(
        model=model,
        vocabs=vocabs,
        config=config,
        metrics=metrics,
        predictions_df=predictions_df,
    )

    print("\nEntrenamiento completado.")
    print(f"Modelo guardado en: {MODEL_PATH}")
    print(f"Vocabularios guardados en: {VOCAB_PATH}")
    print(f"Config guardada en: {CONFIG_PATH}")
    print(f"Métricas guardadas en: {METRICS_PATH}")
    print(f"Reporte guardado en: {REPORT_PATH}")
    print(f"Predicciones guardadas en: {PREDICTIONS_PATH}")

    print("\nMétricas principales:")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Precision anomaly: {metrics['precision_anomaly']:.4f}")
    print(f"Recall anomaly: {metrics['recall_anomaly']:.4f}")
    print(f"F1 anomaly: {metrics['f1_anomaly']:.4f}")

    print("\nMatriz de confusión:")
    print(metrics["confusion_matrix"])


if __name__ == "__main__":
    main()