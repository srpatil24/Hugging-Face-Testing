from datasets import load_dataset, Dataset
from transformers import Trainer, TrainingArguments, AutoTokenizer, AutoModelForCausalLM
from tqdm import tqdm

dataset = load_dataset("vicgalle/alpaca-gpt4")

tokenizer = AutoTokenizer.from_pretrained("nomic-ai/gpt4all-j", revision="v1.2-jazzy")
tokenizer.add_special_tokens({'pad_token': '[PAD]'})

model = AutoModelForCausalLM.from_pretrained("nomic-ai/gpt4all-j", revision="v1.2-jazzy")
model.resize_token_embeddings(tokenizer.vocab_size)

vocab_size = tokenizer.vocab_size

print("VOCAB SIZES")

print(vocab_size)
print(model.config.vocab_size)


if vocab_size != model.config.vocab_size:
    raise ValueError("Tokenizer and model configurations are incompatible.")
else:
    print("Vocab sizes are the same!")

max_length = 1000

def preprocess_function(examples):
    tokenized_inputs = tokenizer(
        examples["text"],
        truncation=True,
        padding="max_length",
        max_length=max_length,
        return_overflowing_tokens=True,
        return_special_tokens_mask=True,
    )

    # Truncate or replace overflowing tokens
    tokenized_inputs["input_ids"] = tokenized_inputs["input_ids"][:max_length]
    tokenized_inputs["attention_mask"] = tokenized_inputs["attention_mask"][:max_length]
    tokenized_inputs["special_tokens_mask"] = tokenized_inputs["special_tokens_mask"][:max_length]

    if len(tokenized_inputs["overflow_to_sample_mapping"]) > 1:
        # Keep only the first and last mapping
        tokenized_inputs["overflow_to_sample_mapping"] = [
            tokenized_inputs["overflow_to_sample_mapping"][0],
            tokenized_inputs["overflow_to_sample_mapping"][-1],
        ]
    else:
        # Pad the mapping to length 1000
        tokenized_inputs["overflow_to_sample_mapping"] = [0] * max_length

    # Replace out-of-vocabulary tokens with [UNK]
    for i, mask in enumerate(tokenized_inputs["special_tokens_mask"]):
        if mask == 1:  # [UNK] token
            tokenized_inputs["input_ids"][i] = tokenizer.unk_token_id

    return tokenized_inputs




preprocessed_dataset = dataset.map(preprocess_function, batched=True)

input_ids = preprocessed_dataset["train"]["input_ids"]
truncated_input_ids = []

for input_id in tqdm(input_ids, desc="Truncating sequences"):
    truncated_input = input_id[:max_length] if len(input_id) > max_length else input_id
    truncated_input_ids.append(truncated_input)

updated_dataset = Dataset.from_dict({"input_ids": truncated_input_ids})

print("STARTING TRAINING")

training_args = TrainingArguments(
    output_dir="./output",
    overwrite_output_dir=True,
    num_train_epochs=3,
    per_device_train_batch_size=4,  # Batch size per GPU/CPU during training
    save_total_limit=2,  # Maximum number of models to save
    learning_rate=5e-5,
    weight_decay=0.01,  # Weight decay for regularization
    logging_dir="./logs",
    logging_steps=100,  # Number of steps between logging updates
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=updated_dataset,
)

trainer.train()
