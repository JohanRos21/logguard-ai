import os
import json
from typing import Dict, List

import torch
import torch.nn as nn


MODEL_DIR = "models/sequence_transformer"
MODEL_PATH = os.path.join(MODEL_DIR, "sequence_transformer.pt")
VOCAB_PATH = os.path.join(MODEL_DIR, "vocab.json")
CONFIG_PATH = os.path.join(MODEL_DIR, "config.json")

DEFAULT_THRESHOLD = 0.50


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

        # Se resume la secuencia ignorando los PAD.
        # Así el resultado representa solo eventos reales.
        valid_mask = (~padding_mask).unsqueeze(-1).float()
        x = x * valid_mask

        summed = x.sum(dim=1)
        counts = valid_mask.sum(dim=1).clamp(min=1.0)
        pooled = summed / counts

        pooled = self.dropout(pooled)
        logits = self.classifier(pooled)

        return logits


def load_json(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"No se encontró el archivo: {path}")

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def load_artifacts():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"No se encontró el modelo: {MODEL_PATH}. Primero ejecuta train_sequence_transformer.py"
        )

    vocabs = load_json(VOCAB_PATH)
    config = load_json(CONFIG_PATH)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    model = LogSequenceTransformer(
        event_vocab_size=len(vocabs["event_vocab"]),
        route_vocab_size=len(vocabs["route_vocab"]),
        status_vocab_size=len(vocabs["status_vocab"]),
        method_vocab_size=len(vocabs["method_vocab"]),
        max_len=config["max_len"],
        embedding_dim=config["embedding_dim"],
        num_heads=config["num_heads"],
        num_layers=config["num_layers"],
        ff_dim=config["ff_dim"],
        dropout=config["dropout"],
        num_classes=len(config["class_names"]),
    ).to(device)

    model.load_state_dict(
        torch.load(MODEL_PATH, map_location=device)
    )

    model.eval()

    return model, vocabs, config, device


def encode_tokens(tokens: List[str], vocab: Dict[str, int], max_len: int) -> List[int]:
    encoded = [
        vocab.get(str(token), vocab["<UNK>"])
        for token in tokens[:max_len]
    ]

    if len(encoded) < max_len:
        encoded += [vocab["<PAD>"]] * (max_len - len(encoded))

    return encoded


def normalize_sequence_input(sequence):
    """
    Permite recibir una secuencia como lista o como texto separado por espacios.

    Ejemplo lista:
    ["login_failed", "login_failed", "unauthorized_access"]

    Ejemplo texto:
    "login_failed login_failed unauthorized_access"
    """

    if isinstance(sequence, list):
        return [str(item) for item in sequence]

    return str(sequence).split()


def predict_sequence(
    event_sequence,
    route_sequence,
    status_sequence,
    method_sequence,
    threshold: float = DEFAULT_THRESHOLD,
):
    model, vocabs, config, device = load_artifacts()

    max_len = config["max_len"]
    class_names = config["class_names"]

    event_tokens = normalize_sequence_input(event_sequence)
    route_tokens = normalize_sequence_input(route_sequence)
    status_tokens = normalize_sequence_input(status_sequence)
    method_tokens = normalize_sequence_input(method_sequence)

    event_ids = encode_tokens(event_tokens, vocabs["event_vocab"], max_len)
    route_ids = encode_tokens(route_tokens, vocabs["route_vocab"], max_len)
    status_ids = encode_tokens(status_tokens, vocabs["status_vocab"], max_len)
    method_ids = encode_tokens(method_tokens, vocabs["method_vocab"], max_len)

    with torch.no_grad():
        event_tensor = torch.tensor([event_ids], dtype=torch.long).to(device)
        route_tensor = torch.tensor([route_ids], dtype=torch.long).to(device)
        status_tensor = torch.tensor([status_ids], dtype=torch.long).to(device)
        method_tensor = torch.tensor([method_ids], dtype=torch.long).to(device)

        logits = model(
            event_tensor,
            route_tensor,
            status_tensor,
            method_tensor,
        )

        probabilities = torch.softmax(logits, dim=1)[0]

    normal_probability = float(probabilities[0].cpu().item())
    anomaly_probability = float(probabilities[1].cpu().item())

    predicted_label = "anomaly" if anomaly_probability >= threshold else "normal"
    predicted_label_id = class_names.index(predicted_label)

    severity_suggestion = infer_severity_suggestion(
        predicted_label=predicted_label,
        anomaly_probability=anomaly_probability,
        event_tokens=event_tokens,
        route_tokens=route_tokens,
        status_tokens=status_tokens,
    )

    return {
        "model": "LogSequenceTransformer",
        "prediction": predicted_label,
        "predicted_label_id": predicted_label_id,
        "normal_probability": normal_probability,
        "anomaly_probability": anomaly_probability,
        "threshold": threshold,
        "severity_suggestion": severity_suggestion,
        "sequence_length": len(event_tokens),
    }


def infer_severity_suggestion(
    predicted_label: str,
    anomaly_probability: float,
    event_tokens: List[str],
    route_tokens: List[str],
    status_tokens: List[str],
):
    """
    El Transformer predice normal/anomaly.
    Esta función agrega una sugerencia de severidad usando señales de negocio.
    """

    if predicted_label == "normal":
        return "normal"

    critical_events = {
        "payment_failed",
        "database_timeout",
        "unauthorized_access",
        "server_error",
    }

    critical_routes = {
        "/api/payments",
        "/api/database",
        "/api/admin/users",
        "/dashboard/admin",
        "/api/enrollments",
    }

    has_critical_event = any(event in critical_events for event in event_tokens)
    has_critical_route = any(route in critical_routes for route in route_tokens)
    has_5xx = any(str(status).startswith("5") for status in status_tokens)

    if anomaly_probability >= 0.85:
        return "critical"

    if has_critical_event and (has_critical_route or has_5xx):
        return "critical"

    return "warning"


def main():
    normal_example = {
        "event_sequence": [
            "login_success",
            "page_view",
            "data_loaded",
            "page_view",
            "record_created",
            "data_loaded",
            "page_view",
            "login_success",
            "data_loaded",
            "page_view",
            "record_created",
            "data_loaded",
            "page_view",
            "login_success",
            "data_loaded",
            "page_view",
            "record_created",
            "data_loaded",
            "page_view",
            "login_success",
        ],
        "route_sequence": [
            "/login",
            "/dashboard",
            "/api/profile",
            "/dashboard/alumno",
            "/api/students",
            "/api/products",
            "/api/reports",
            "/login",
            "/api/profile",
            "/dashboard",
            "/api/students",
            "/api/products",
            "/api/reports",
            "/login",
            "/api/profile",
            "/dashboard",
            "/api/students",
            "/api/products",
            "/api/reports",
            "/dashboard",
        ],
        "status_sequence": [
            "200", "200", "200", "200", "201",
            "200", "200", "200", "200", "200",
            "201", "200", "200", "200", "200",
            "200", "201", "200", "200", "200",
        ],
        "method_sequence": [
            "POST", "GET", "GET", "GET", "POST",
            "GET", "GET", "POST", "GET", "GET",
            "POST", "GET", "GET", "POST", "GET",
            "GET", "POST", "GET", "GET", "GET",
        ],
    }

    anomaly_example = {
        "event_sequence": [
            "login_failed",
            "login_failed",
            "login_failed",
            "login_failed",
            "login_failed",
            "unauthorized_access",
            "unauthorized_access",
            "page_view",
            "login_failed",
            "unauthorized_access",
            "server_error",
            "page_view",
            "data_loaded",
            "login_failed",
            "unauthorized_access",
            "page_view",
            "server_error",
            "login_failed",
            "unauthorized_access",
            "page_view",
        ],
        "route_sequence": [
            "/login",
            "/login",
            "/login",
            "/login",
            "/login",
            "/dashboard/admin",
            "/api/admin/users",
            "/dashboard",
            "/login",
            "/dashboard/admin",
            "/api/admin/users",
            "/",
            "/api/profile",
            "/login",
            "/dashboard/admin",
            "/dashboard",
            "/api/admin/users",
            "/login",
            "/dashboard/admin",
            "/",
        ],
        "status_sequence": [
            "401", "401", "401", "401", "401",
            "403", "403", "200", "401", "403",
            "500", "200", "200", "401", "403",
            "200", "500", "401", "403", "200",
        ],
        "method_sequence": [
            "POST", "POST", "POST", "POST", "POST",
            "GET", "GET", "GET", "POST", "GET",
            "GET", "GET", "GET", "POST", "GET",
            "GET", "GET", "POST", "GET", "GET",
        ],
    }

    print("Predicción para secuencia normal:")
    print(predict_sequence(**normal_example))

    print("\nPredicción para secuencia anómala:")
    print(predict_sequence(**anomaly_example))


if __name__ == "__main__":
    main()