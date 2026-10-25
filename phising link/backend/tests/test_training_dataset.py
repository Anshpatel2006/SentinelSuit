import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

import pandas as pd

import main


class TrainingDatasetTests(unittest.TestCase):
    def test_configured_training_dataset_is_present(self):
        self.assertTrue(main.DATASET_PATH.is_file())

    def test_url_columns_use_the_live_feature_extractor(self):
        url = "http://example.com/login/secure"
        row = {feature: 0 for feature in main.FEATURES}
        row.update({"URL": url, "ClassLabel": 0})
        with TemporaryDirectory() as directory:
            dataset = Path(directory) / "training.csv"
            pd.DataFrame([row]).to_csv(dataset, index=False)
            features, labels, _ = main.prepare_dataset(dataset)

        expected = main.extract_features(main.normalize_url(url)).iloc[0]
        pd.testing.assert_series_equal(
            features.iloc[0],
            expected,
            check_names=False,
            check_dtype=False,
        )
        self.assertEqual(int(labels.iloc[0]), 1)


if __name__ == "__main__":
    unittest.main()
