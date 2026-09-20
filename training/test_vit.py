from transformers import ViTImageProcessor, ViTForImageClassification

MODEL_NAME = "google/vit-base-patch16-224"

print("Loading processor...")
processor = ViTImageProcessor.from_pretrained(MODEL_NAME)

print("Loading model...")
model = ViTForImageClassification.from_pretrained(MODEL_NAME)

print("ViT loaded successfully!")
print("Number of labels:", model.config.num_labels)