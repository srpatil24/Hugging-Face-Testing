from datasets import load_dataset
from transformers import Trainer, TrainingArguments, AutoTokenizer, AutoModelForCausalLM
from bs4 import BeautifulSoup

dataset = load_dataset("vicgalle/alpaca-gpt4")

tokenizer = AutoTokenizer.from_pretrained("nomic-ai/gpt4all-j")
tokenizer.add_special_tokens({'pad_token': '[PAD]'})

model = AutoModelForCausalLM.from_pretrained("nomic-ai/gpt4all-j")

def preprocess_function(examples):
    tokenized_inputs = tokenizer(
        examples["text"],
        truncation=True,
        padding="max_length",
        max_length=2048
    )
    return tokenized_inputs

preprocessed_dataset = dataset.map(preprocess_function, batched=True)

# Clean the input values
for i in range(len(preprocessed_dataset["train"]["input"])):
    html_text = preprocessed_dataset["train"]["input"][i]
    soup = BeautifulSoup(html_text, 'html.parser')
    clean_text = soup.get_text()
    preprocessed_dataset["train"]["input"][i] = clean_text

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
    model=model,  # The pre-trained model to be fine-tuned
    args=training_args,  # Training arguments
    train_dataset=preprocessed_dataset["train"],  # Training dataset
)

#trainer.train()