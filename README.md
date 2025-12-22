# Thesis Appendix

Appendix scripts for the master thesis "Assessing the Real-World Relevance of Capture-The-Flag (CTF) Challenges Using NICE and MITRE ATT&CK Frameworks".
This repository is archived to perserve its state upon publishing the thesis.

## Overview

This repository contains all scripts from my master thesis.
The scripts quantify the real-world applicability of CTF challenges, but changes to the baseline will quantify the similarity to your chosen metric.
The framework maps CTF challenges to MITRE ATT&CK techniques, which are then weighted against NICE workforce framework categories to compute similarity scores and probability metrics.

## Repository Structure

```
├── app/                          # Main application scripts
│   ├── challenge_parser.py       # Parse and analyze challenge mappings
│   ├── create_M_matrix.py        # Generate MITRE-to-NICE mapping matrix
│   ├── likeness_model.py         # Core similarity calculation engine
│   ├── parse_challenge_probabilities.py  # Calculate probabilities for challenges
│   ├── punish_test.py            # Run iterative punishment tests
│   └── train_alfa_beta.py        # Train logistic regression parameters
│
├── baseline_files/               # Reference data and mappings
│   ├── alpha_beta_params.yaml    # Trained α and β parameters
│   ├── baseline.yaml             # Baseline MITRE technique weights
│   ├── challenge_similarity_results.yaml  # Analysis results
│   ├── CWE-OWASP-to-MITRE.yml   # CWE/OWASP to MITRE mappings
│   ├── HHC_NW_training.yaml     # Training challenge dataset
│   ├── MITRE-to-NICE-M-matrix.csv  # Computed mapping matrix
│   ├── MITRE-to-NICE-raw.csv    # Raw MITRE-NICE relationships
│   └── NICE_Weighting.csv        # NICE category weights
│
├── .gitignore
└── README.md
```

## Key Components

### Core Scripts

- **`likeness_model.py`**: Main engine for calculating real-world likeness
  - Loads challenge metadata from YAML files
  - Creates C matrices (MITRE technique weight vectors)
  - Computes N vectors (NICE mappings)
  - Calculates cosine similarity and probability scores

- **`create_M_matrix.py`**: Generates the MITRE-to-NICE mapping matrix
  - Processes NICE weighting factors
  - Creates weighted transformation matrix
  - Outputs column sums for analysis

- **`challenge_parser.py`**: Batch analysis tool
  - Processes multiple challenges from YAML files
  - Generates similarity scores against baseline
  - Produces comprehensive analysis reports

- **`train_alfa_beta.py`**: Trains logistic regression parameters
  - Uses labeled challenge data
  - Optimizes α and β parameters for probability calculation
  - Saves parameters to `alpha_beta_params.yaml`

- **`parse_challenge_probabilities.py`**: Repository scanner
  - Scans directories for challenge YAML files
  - Calculates probabilities for each challenge
  - Outputs results to CSV format

- **`punish_test.py`**: Iterative testing framework
  - Runs multiple punishment iterations
  - Updates weights and recalculates metrics
  - Generates comprehensive logs

### Data Files

- **`CWE-OWASP-to-MITRE.yml`**: Mapping of CWE vulnerabilities and OWASP categories to MITRE ATT&CK techniques
- **`NICE_Weighting.csv`**: Weights for NICE framework categories based on training data
- **`baseline.yaml`**: Reference baseline computed from CWE/OWASP mappings
- **`HHC_NW_training.yaml`**: Training dataset with labeled challenges

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd Thesis_Appendix

# Install required dependencies
pip install numpy scipy scikit-learn pyyaml
#or
pip install -r ./requirements.txt
```

## Usage

The model is dependant on the baseline files to assign the correct weights.
If you want to change the weightings on of what you consider important, update their weights in `NICE_Weighting.csv`.
The csv file `MITRE-to-NICE-raw.csv` is ment to do MITRE tagging, assign own tags here if you want anything else than the vulnerability assessment nice role and basic hacking mitre tags.
With the baseline ready, run `create_M_matrix.py` to create the M matrix.
Then generate the baseline for the model `./likeness_model.py --baseline ../baseline_files/CWE-OWASP-to-MITRE.yml`
Now you can create similarity scores.
However, you need to create alpha and beta to calculate the probability.
The script `./challenge_parser.py` will parse the Holiday Hack and NetWars baseline. This will be used for the alpha and beta training.
The script `/train_alfa_beta.py` will train alpha and beta, now you are ready to run the probability calculations.
Parsing an entire repo can be done with `parse_challenge_probabilities.py -r ~/githubchallengerepo/`.
This can also be done with a single challenge `likeness_model.py path/to/challenge.yaml`.

These steps are not required if you don't want to recalculate anything. 
You can skip straight to `parse_challenge_probabilities.py` or `likeness_model.py`.

### Calculate Single Challenge Probability

```bash
python likeness_model.py path/to/challenge.yaml
```

### Generate Baseline from CWE/OWASP Mappings

```bash
python likeness_model.py baseline_files/CWE-OWASP-to-MITRE.yml --baseline
```

### Calculate Similarity Score

```bash
python likeness_model.py path/to/challenge.yaml --similarity
```

### Process Multiple Challenges

```bash
# From a repository
python parse_challenge_probabilities.py -r /path/to/challenges/repo

# From a specific YAML file
python parse_challenge_probabilities.py -cy path/to/challenge.yaml
```

### Run Punishment Iterations

```bash
python punish_test.py -i 97 -r /path/to/challenges/repo
```

### Train α and β Parameters

```bash
python train_alfa_beta.py
```

## Methodology

The framework uses a three-step process:

1. **Challenge Mapping**: CTF challenges are mapped to MITRE ATT&CK techniques with difficulty weights
2. **NICE Transformation**: MITRE techniques are transformed to NICE categories using a weighted matrix
3. **Similarity Calculation**: Cosine similarity is computed against a baseline, then converted to probability using logistic regression

The probability formula is:
```
P = 1 / (1 + exp(-α * S + β))
```
where S is the cosine similarity score, and α and β are trained parameters.

## Challenge YAML Format

```yaml
challenge_name: "Example Challenge"
category: "Web Exploitation"
difficulty: 0.6 # Overall difficulty or per tactic difficulty is accepted
mitre_tactics:
  - technique_id: T1190
    difficulty: 0.5
  - technique_id: T1059
    difficulty: 0.7
```

## Output Formats

### Similarity Analysis
Results are saved to `challenge_similarity_results.yaml` with:
- Similarity scores
- Probability values
- Challenge metadata
- Summary statistics

### CSV Output
`probability_weights.csv` contains:
- Challenge name
- Similarity score
- Calculated probability

## Parameters

Current trained parameters (from `alpha_beta_params.yaml`):
- **α**: 2.0193311079775227
- **β**: -0.23003546324143453

## Contributing

This repository contains research code for the master thesis "Assessing the Real-World Relevance of Capture-The-Flag (CTF) Challenges Using NICE and MITRE ATT&CK Frameworks."
Feel free to fork it.
