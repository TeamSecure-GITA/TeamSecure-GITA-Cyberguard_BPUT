"""Optional Flower federated-learning entry point.

Run after installing requirements-ai.txt. Each client reads only its local CSV;
server-side aggregation receives model parameters, never raw messages.
"""
import argparse
import csv
import os
from pathlib import Path

import numpy as np
from federated_training import redact

try:
    import flwr as fl
    from sklearn.feature_extraction.text import HashingVectorizer
    from sklearn.linear_model import SGDClassifier
except ImportError as error:
    raise SystemExit("Install requirements-ai.txt to run the Flower integration: " + str(error))


def load_local_dataset(dataset: Path):
    with dataset.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError("Client dataset must contain labeled text rows")
    texts = []
    labels = []
    for row in rows:
        text = (row.get("text") or "").strip()
        try:
            label = int(row["label"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("Client dataset must contain text,label columns with integer labels") from error
        if not text or label not in {0, 1}:
            raise ValueError("Client dataset rows require non-empty text and label 0 or 1")
        texts.append(redact(text))
        labels.append(label)
    if set(labels) != {0, 1}:
        raise ValueError("Each client dataset must include both benign (0) and suspicious (1) examples")
    return texts, np.asarray(labels)


def load_server_certificates(ca_cert: Path | None, server_cert: Path | None, server_key: Path | None):
    paths = (ca_cert, server_cert, server_key)
    if all(path is None for path in paths):
        return None
    if any(path is None for path in paths):
        raise ValueError("TLS server mode requires CA certificate, server certificate, and server key")
    try:
        return tuple(path.read_bytes() for path in paths)
    except OSError as error:
        raise ValueError(f"Could not read Flower TLS certificate material: {error}") from error


def _is_loopback(address: str) -> bool:
    host = address.rsplit(":", 1)[0].strip("[]").lower()
    return host in {"localhost", "127.0.0.1", "::1"}


class CyberGuardClient(fl.client.NumPyClient):
    def __init__(self, dataset: Path):
        texts, self.y = load_local_dataset(dataset)
        self.x = HashingVectorizer(n_features=2**12, alternate_sign=False).transform(texts)
        self.model = SGDClassifier(loss="log_loss", max_iter=1, random_state=42)
        self.model.partial_fit(self.x, self.y, classes=np.array([0, 1]))

    def get_parameters(self, config):
        return [self.model.coef_, self.model.intercept_]

    def fit(self, parameters, config):
        self.model.coef_, self.model.intercept_ = parameters
        self.model.partial_fit(self.x, self.y)
        return self.get_parameters(config), len(self.y), {}

    def evaluate(self, parameters, config):
        self.model.coef_, self.model.intercept_ = parameters
        return float(1 - self.model.score(self.x, self.y)), len(self.y), {"accuracy": float(self.model.score(self.x, self.y))}


def start_server(rounds: int, bind_address: str, min_clients: int, certificates=None, allow_insecure: bool = False):
    if rounds < 1 or min_clients < 2:
        raise ValueError("Federated training needs at least one round and two available clients")
    if certificates is None and not _is_loopback(bind_address) and not allow_insecure:
        raise ValueError("Non-loopback Flower servers require TLS certificates; use --allow-insecure only for isolated demos")
    strategy = fl.server.strategy.FedAvg(min_fit_clients=min_clients, min_available_clients=min_clients, min_evaluate_clients=min_clients)
    fl.server.start_server(server_address=bind_address, config=fl.server.ServerConfig(num_rounds=rounds), strategy=strategy, certificates=certificates)


def start_client(dataset: Path, server_address: str, root_certificate: Path | None = None, allow_insecure: bool = False):
    if root_certificate is None and not _is_loopback(server_address) and not allow_insecure:
        raise ValueError("Remote Flower clients require a trusted root certificate; use --allow-insecure only for isolated demos")
    root_certificates = root_certificate.read_bytes() if root_certificate else None
    fl.client.start_client(
        server_address=server_address,
        client=CyberGuardClient(dataset).to_client(),
        root_certificates=root_certificates,
        insecure=root_certificates is None,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["server", "client"])
    parser.add_argument("--data", type=Path)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--min-clients", type=int, default=3)
    parser.add_argument("--bind-address", default=os.getenv("CYBERGUARD_FLOWER_BIND_ADDRESS", "0.0.0.0:8080"))
    parser.add_argument("--server-address", default=os.getenv("CYBERGUARD_FLOWER_SERVER_ADDRESS", "127.0.0.1:8080"))
    parser.add_argument("--ca-cert", type=Path)
    parser.add_argument("--server-cert", type=Path)
    parser.add_argument("--server-key", type=Path)
    parser.add_argument("--root-cert", type=Path)
    parser.add_argument("--allow-insecure", action="store_true", help="Allow plaintext gRPC for isolated demos only")
    args = parser.parse_args()
    if args.mode == "server":
        try:
            certificates = load_server_certificates(args.ca_cert, args.server_cert, args.server_key)
            start_server(args.rounds, args.bind_address, args.min_clients, certificates, args.allow_insecure)
        except ValueError as error:
            parser.error(str(error))
    elif not args.data:
        parser.error("--data is required in client mode")
    else:
        try:
            start_client(args.data, args.server_address, args.root_cert, args.allow_insecure)
        except (OSError, ValueError) as error:
            parser.error(str(error))
