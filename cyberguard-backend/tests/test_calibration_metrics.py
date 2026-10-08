import pytest

from calibration_metrics import probability_calibration
from evaluate_media_dataset import calculate_metrics


def test_probability_calibration_reports_brier_and_reliability_bins():
    result = probability_calibration([0, 1], [0.2, 0.8])

    assert result["expected_calibration_error"] == pytest.approx(0.2)
    assert result["brier_score"] == pytest.approx(0.04)
    assert result["bin_count"] == 10
    assert len(result["reliability_bins"]) == 2


def test_media_metrics_report_probability_calibration():
    result = calculate_metrics([
        {"label": 0, "score": 20, "modality": "image"},
        {"label": 1, "score": 80, "modality": "image"},
    ])

    assert result["calibration"]["expected_calibration_error"] == pytest.approx(0.2)
    assert result["calibration"]["brier_score"] == pytest.approx(0.04)


@pytest.mark.parametrize("labels,probabilities", [
    ([], []),
    ([0], [float("nan")]),
    ([0], [1.1]),
    ([2], [0.5]),
])
def test_probability_calibration_rejects_invalid_inputs(labels, probabilities):
    with pytest.raises(ValueError):
        probability_calibration(labels, probabilities)
