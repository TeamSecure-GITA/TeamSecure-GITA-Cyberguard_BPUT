---
license: apache-2.0
base_model: facebook/wav2vec2-base
tags:
- generated_from_trainer
datasets:
- audiofolder
metrics:
- accuracy
model-index:
- name: Deeepfake-audio
  results:
  - task:
      name: Audio Classification
      type: audio-classification
    dataset:
      name: audiofolder
      type: audiofolder
      config: default
      split: train
      args: default
    metrics:
    - name: Accuracy
      type: accuracy
      value: 0.9545454545454546
---

<!-- This model card has been generated automatically according to the information the Trainer had access to. You
should probably proofread and complete it, then remove this comment. -->

# deeepfake-audio-Recognition

This model is a fine-tuned version of [facebook/wav2vec2-base](https://huggingface.co/facebook/wav2vec2-base) on the audiofolder dataset.
It achieves the following results on the evaluation set:
- Loss: 0.2288
- Accuracy: 0.9545

## Model description

* The model is fintune on facebook/wav2vec2-base


## Intended uses & limitations

* The model still needs dataset to increase model accuracy.
## Training and evaluation data

* The model is trained on multi-ethnic english dataset.
* The input audio dataset is about 16KHz.

### Framework versions

- Transformers 4.39.2
- Pytorch 2.2.1+cu121
- Datasets 2.18.0
- Tokenizers 0.15.2
