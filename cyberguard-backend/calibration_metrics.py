"""Calibration metrics shared by text and media benchmark runners."""
import math


def probability_calibration(labels: list[int], probabilities: list[float], bins: int = 10) -> dict:
    """Return fixed-width reliability bins, expected calibration error, and Brier score."""
    if len(labels) != len(probabilities) or not labels:
        raise ValueError("Calibration requires equally sized, non-empty labels and probabilities")
    if bins < 1 or any(label not in (0, 1) for label in labels):
        raise ValueError("Calibration labels must be binary and bins must be positive")
    if any(not math.isfinite(float(value)) or not 0 <= float(value) <= 1 for value in probabilities):
        raise ValueError("Calibration probabilities must be finite values between 0 and 1")

    reliability = []
    expected_calibration_error = 0.0
    sample_count = len(labels)
    for index in range(bins):
        lower = index / bins
        upper = (index + 1) / bins
        selected = [
            (int(label), float(probability))
            for label, probability in zip(labels, probabilities)
            if lower <= float(probability) < upper
            or (index == bins - 1 and float(probability) == 1.0)
        ]
        if not selected:
            continue
        mean_probability = sum(probability for _, probability in selected) / len(selected)
        observed_rate = sum(label for label, _ in selected) / len(selected)
        expected_calibration_error += len(selected) / sample_count * abs(mean_probability - observed_rate)
        reliability.append({
            "lower_bound": lower,
            "upper_bound": upper,
            "samples": len(selected),
            "mean_probability": mean_probability,
            "observed_positive_rate": observed_rate,
        })

    brier_score = sum(
        (float(probability) - int(label)) ** 2
        for label, probability in zip(labels, probabilities)
    ) / sample_count
    return {
        "method": "fixed_width_probability_bins",
        "bin_count": bins,
        "expected_calibration_error": expected_calibration_error,
        "brier_score": brier_score,
        "reliability_bins": reliability,
    }
