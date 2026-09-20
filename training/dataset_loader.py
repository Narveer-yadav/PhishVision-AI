from pathlib import Path
from PIL import Image
from torch.utils.data import Dataset
from transformers import ViTImageProcessor

# -----------------------------
# Configuration
# -----------------------------
MODEL_NAME = "google/vit-base-patch16-224"

DATASET_DIR = Path("dataset")

LABELS = {
    "legitimate": 0,
    "phishing": 1
}

# Load ViT processor
processor = ViTImageProcessor.from_pretrained(MODEL_NAME)


class PhishingDataset(Dataset):

    def __init__(self, split):

        self.image_paths = []
        self.labels = []

        split_dir = DATASET_DIR / split

        if not split_dir.exists():
            raise FileNotFoundError(
                f"Dataset split not found: {split_dir}"
            )

        # Load images from each class
        for class_name, label in LABELS.items():

            class_dir = split_dir / class_name

            if not class_dir.exists():
                raise FileNotFoundError(
                    f"Class folder not found: {class_dir}"
                )

            for image_path in class_dir.iterdir():

                if image_path.is_file():
                    self.image_paths.append(image_path)
                    self.labels.append(label)

        print(f"{split} dataset loaded: {len(self.image_paths)} images")

    def __len__(self):
        return len(self.image_paths)

    def __getitem__(self, index):

        image_path = self.image_paths[index]
        label = self.labels[index]

        # Open image
        image = Image.open(image_path).convert("RGB")

        # ViT preprocessing
        inputs = processor(
            images=image,
            return_tensors="pt"
        )

        # Remove batch dimension
        pixel_values = inputs["pixel_values"].squeeze(0)

        return {
            "pixel_values": pixel_values,
            "labels": label
        }


# -----------------------------
# Test the datasets
# -----------------------------
if __name__ == "__main__":

    train_dataset = PhishingDataset("train")
    validation_dataset = PhishingDataset("validation")
    test_dataset = PhishingDataset("test")

    print("\nDataset verification:")
    print("Train:", len(train_dataset))
    print("Validation:", len(validation_dataset))
    print("Test:", len(test_dataset))

    # Test one image
    sample = train_dataset[0]

    print("\nSample verification:")
    print("Pixel shape:", sample["pixel_values"].shape)
    print("Label:", sample["labels"])

    print("\nDataset loader working successfully!")