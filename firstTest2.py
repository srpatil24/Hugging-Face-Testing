from datasets import load_dataset, Dataset
from transformers import Trainer, TrainingArguments, AutoTokenizer, AutoModelForCausalLM
from tqdm import tqdm
import datetime

now = datetime.datetime.now()
print ("Current date and time : ")
print (now.strftime("%Y-%m-%d %H:%M:%S"))

dataset = load_dataset("databricks/databricks-dolly-15k", split="train")

dataset = dataset.remove_columns(["context"])
dataset = dataset.rename_columns({'instruction': 'prompt', 'category': 'source'})

tokenizer = AutoTokenizer.from_pretrained("nomic-ai/gpt4all-j", revision="v1.2-jazzy")
tokenizer.add_special_tokens({'pad_token': '[PAD]'})

model = AutoModelForCausalLM.from_pretrained("nomic-ai/gpt4all-j", revision="v1.2-jazzy")
model.resize_token_embeddings(tokenizer.vocab_size)

vocab_size = tokenizer.vocab_size

embedding_dim = model.config.hidden_size

print("VOCAB SIZES")

print(vocab_size)
print(model.config.vocab_size)


if vocab_size != model.config.vocab_size:
    raise ValueError("Tokenizer and model configurations are incompatible.")
else:
    print("Vocab sizes are the same!")

max_length = 1000

# Fine-tuning configuration
training_args = TrainingArguments(
    output_dir="./results",
    overwrite_output_dir=True,
    num_train_epochs=1,
    per_device_train_batch_size=2,
    save_steps=500,
    save_total_limit=2,
    prediction_loss_only=True,
    learning_rate=1e-4,
    weight_decay=0.01,
    logging_steps=100,
    logging_first_step=True,
    warmup_steps=500,
    seed=42,
)

# Define a function to preprocess the data
# Define a function to preprocess the data
def preprocess_function(examples, max_length):
    inputs = examples["prompt"]
    outputs = examples["response"]
    tokenized_inputs = tokenizer(inputs, truncation=True, padding="max_length", max_length=max_length, return_tensors="pt")
    tokenized_outputs = tokenizer(outputs, truncation=True, padding="max_length", max_length=max_length, return_tensors="pt")

    input_ids = tokenized_inputs["input_ids"].squeeze()[:max_length]
    attention_mask = tokenized_inputs["attention_mask"].squeeze()[:max_length]
    labels = tokenized_outputs["input_ids"].squeeze()[:max_length]

    # Ensure all input tensors have the same size
    input_ids = input_ids[:max_length]
    attention_mask = attention_mask[:max_length]
    labels = labels[:max_length]

    input_ids = input_ids.masked_fill(input_ids >= vocab_size, tokenizer.unk_token_id)
    labels = labels.masked_fill(labels >= vocab_size, tokenizer.unk_token_id)

    return {
        "input_ids": input_ids,
        "attention_mask": attention_mask,
        "labels": labels,
    }



# Apply the preprocess function to the dataset
preprocessed_dataset = dataset.map(lambda examples: preprocess_function(examples, max_length), batched=True)

model.resize_token_embeddings(len(tokenizer))

# Initialize the Trainer
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=preprocessed_dataset,
)

# Start the fine-tuning process
trainer.train()

