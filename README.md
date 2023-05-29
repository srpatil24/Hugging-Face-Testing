# Objectives
The objective of this repository is to fine-tune pretrained huggingface models on freely available huggingface datasets to further improve their performance on tasks such as
* Classification
* Q&A
* Brainstorming
* Summarization
* etc.

# What has been done so far
Scripts have been written to fine-tune [nomic-ai/gpt4all-j](https://huggingface.co/nomic-ai/gpt4all-j) on:
* [databricks/databricks-dolly-15k](https://huggingface.co/datasets/databricks/databricks-dolly-15k)
* [vicgalle/alpaca-gpt4](https://huggingface.co/datasets/vicgalle/alpaca-gpt4)

# Problems
Both scripts require a powerful computer. 8GB VRAM is not enough; have not been able to fully fine-tune as of yet due to this.
