from pathlib import Path
from PIL import Image
import random
import shutil

# -----------------------------
# Configuration
# -----------------------------
DATASET_DIR = Path("dataset")

SOURCE_DIRS = {
    "phishing": DATASET_DIR / "phishing",
    "legitimate": DATASET_DIR / "legitimate"
}

SPLITS = {
    "train": 0.80,
    "validation": 0.10,
    "test": 0.10
}

RANDOM_SEED = 42

# -----------------------------
# Check source folders
# -----------------------------
for class_name, folder in SOURCE_DIRS.items():
    if not folder.exists():
        raise FileNotFoundError(f"Folder not found: {folder}")

# -----------------------------
# Remove old split folders
# -----------------------------
for split in SPLITS:
    split_dir = DATASET_DIR / split

    if split_dir.exists():
        shutil.rmtree(split_dir)

# -----------------------------
# Random seed
# -----------------------------
random.seed(RANDOM_SEED)

# -----------------------------
# Process each class
# -----------------------------
for class_name, source_folder in SOURCE_DIRS.items():

    images = []

    for file in source_folder.iterdir():

        if not file.is_file():
            continue

        try:
            # Check whether image is valid
            with Image.open(file) as img:
                img.verify()

            images.append(file)

        except Exception:
            print(f"Skipping invalid image: {file}")

    # Shuffle images
    random.shuffle(images)

    total = len(images)

    train_end = int(total * SPLITS["train"])
    validation_end = train_end + int(total * SPLITS["validation"])

    train_images = images[:train_end]
    validation_images = images[train_end:validation_end]
    test_images = images[validation_end:]

    split_data = {
        "train": train_images,
        "validation": validation_images,
        "test": test_images
    }

    # -----------------------------
    # Copy images
    # -----------------------------
    for split, split_images in split_data.items():

        destination = DATASET_DIR / split / class_name
        destination.mkdir(parents=True, exist_ok=True)

        for image in split_images:
            shutil.copy2(image, destination / image.name)

    # -----------------------------
    # Print results
    # -----------------------------
    print(f"\nClass: {class_name}")
    print(f"Total:      {total}")
    print(f"Train:      {len(train_images)}")
    print(f"Validation: {len(validation_images)}")
    print(f"Test:       {len(test_images)}")

print("\nDataset preparation completed successfully!")