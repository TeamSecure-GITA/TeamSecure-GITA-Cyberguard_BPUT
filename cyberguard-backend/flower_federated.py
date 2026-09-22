"""Optional Flower federated-learning entry point.

Run after installing requirements-ai.txt. Each client reads only its local CSV;
server-side aggregation receives model parameters, never raw messages.
"""
import argparse
import csv
from pathlib import Path

import numpy as np

try:
    import flwr as fl
    from sklearn.feature_extraction.text import HashingVectorizer
    from sklearn.linear_model import SGDClassifier
except ImportError as error:
    raise SystemExit("Install requirements-ai.txt to run the Flower integration: " + str(error))


class CyberGuardClient(fl.client.NumPyClient):
    def __init__(self, dataset: Path):
        with dataset.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.x = HashingVectorizer(n_features=2**12, alternate_sign=False).transform([row["text"] for row in rows])
        self.y = np.array([int(row["label"]) for row in rows])
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


def start_server(rounds: int):
    strategy = fl.server.strategy.FedAvg(min_fit_clients=3, min_available_clients=3, min_evaluate_clients=3)
    fl.server.start_server(server_address="0.0.0.0:8080", config=fl.server.ServerConfig(num_rounds=rounds), strategy=strategy)


def start_client(dataset: Path):
    fl.client.start_client(server_address="127.0.0.1:8080", client=CyberGuardClient(dataset).to_client())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["server", "client"])
    parser.add_argument("--data", type=Path)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    if args.mode == "server":
        start_server(args.rounds)
    elif not args.data:
        parser.error("--data is required in client mode")
    else:
        start_client(args.data)
