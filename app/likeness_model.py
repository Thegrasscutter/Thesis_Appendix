import numpy as np
import yaml
import argparse
import sys

Silent = False
MITRE_INDEX_MAPPING = {}

def load_yaml(file_path):
    global Silent
    """Loads CTF challenge metadata from a YAML file."""
    with open(file_path, "r") as file:
        if Silent:
            return yaml.safe_load(file)
        else:
            print(f"[+] Loading challenge data from {file_path}")
            return yaml.safe_load(file)

def write_yaml(data, file_path):
    global Silent
    """Saves data to a YAML file."""
    with open(file_path, "w") as file:
        yaml.dump(data, file, default_flow_style=False, sort_keys=False)
        if not Silent:
            print(f"[+] Data successfully written to {file_path}")

def create_C_matrix(challenge_data):
    global Silent
    """Constructs the C matrix (MITRE technique weight vector)."""
    difficulty = challenge_data.get("difficulty", 0.5)
    mitre_tactics = challenge_data["mitre_tactics"]

    # Placeholder for full MITRE vector (initialized to 0)
    C = np.zeros(len(MITRE_INDEX_MAPPING))

    # Assign challenge-specific weights
    for tactic in mitre_tactics:
        technique_id = tactic["technique_id"]
        #if not Silent:
            #print(f"[+] Processing technique: {technique_id}")
        
        # Check if this tactic has its own difficulty value
        tactic_difficulty = tactic.get("difficulty", difficulty)
        
        # First check if the technique ID exists directly in the mapping
        if technique_id in MITRE_INDEX_MAPPING:
            mitre_index = MITRE_INDEX_MAPPING[technique_id]
            # Check if relevance_weight is present in the tactic
            if "relevance_weight" not in tactic or tactic["relevance_weight"] is None:
                C[mitre_index] = tactic_difficulty
            else:
                C[mitre_index] = tactic["relevance_weight"] * tactic_difficulty
        else:
            # Try to find the technique ID as a string in the keys
            found = False
            for key in MITRE_INDEX_MAPPING:
                # Convert both to strings for comparison
                if str(key) == str(technique_id):
                    mitre_index = MITRE_INDEX_MAPPING[key]
                    found = True
                    # Check if relevance_weight is present in the tactic
                    if "relevance_weight" not in tactic or tactic["relevance_weight"] is None:
                        C[mitre_index] = tactic_difficulty
                    else:
                        C[mitre_index] = tactic["relevance_weight"] * tactic_difficulty
                    break
            
            if not found:
                print(f"[-] ERROR: Unknown technique ID: {technique_id}. Skipping")
                continue
    if Silent:
        return C
    else:
        print(f"[+] Computed C matrix with shape {C.shape}")
        return C

def generate_baseline(yaml_file_path, difficulty=1.0):
    """
    Parse a YAML file containing CWE and OWASP mappings to MITRE tactics.
    Extract all unique MITRE tactics and create entries with relevance_weight.
    
    Args:
        yaml_file_path (str): Path to the YAML file
        difficulty (float): Default difficulty to use for relevance weight
        
    Returns:
        dict: Challenge data structure with unique MITRE tactics
    """
    if not Silent:
        print(f"[+] Loading MITRE mappings from {yaml_file_path}")
    
    # Load the YAML file
    data = load_yaml(yaml_file_path)
    
    # Set to store unique MITRE tactics
    unique_tactics = set()
    
    # Process CWE mappings
    if 'cwe_mappings' in data:
        # Dictionary to track tactics and their weights
        tactic_weights = {}
        tactic_counts = {}
        
        for cwe_id, cwe_info in data['cwe_mappings'].items():
            if 'mitre_tactics' in cwe_info:
                # Get the CWE difficulty as weight if available
                cwe_weight = cwe_info.get('difficulty', difficulty)
                
                for tactic in cwe_info['mitre_tactics']:
                    tactic_str = str(tactic)
                    unique_tactics.add(tactic_str)
                    
                    # Track the weights for averaging later
                    if tactic_str not in tactic_weights:
                        tactic_weights[tactic_str] = cwe_weight
                        tactic_counts[tactic_str] = 1
                    else:
                        tactic_weights[tactic_str] += cwe_weight
                        tactic_counts[tactic_str] += 1
    
    # Process OWASP mappings
    if 'owasp_mappings' in data:
        for owasp_id, owasp_info in data['owasp_mappings'].items():
            if 'mitre_tactics' in owasp_info:
                # Get the OWASP difficulty as weight if available
                owasp_weight = owasp_info.get('difficulty', difficulty)
                
                for tactic in owasp_info['mitre_tactics']:
                    tactic_str = str(tactic)
                    unique_tactics.add(tactic_str)
                    
                    # Track the weights for averaging later
                    if tactic_str not in tactic_weights:
                        tactic_weights[tactic_str] = owasp_weight
                        tactic_counts[tactic_str] = 1
                    else:
                        tactic_weights[tactic_str] += owasp_weight
                        tactic_counts[tactic_str] += 1
    
    # Calculate average weights and create the tactics list
    mitre_tactics = []
    for tactic in unique_tactics:
        avg_weight = tactic_weights.get(tactic, difficulty) / tactic_counts.get(tactic, 1)
        mitre_tactics.append({"technique_id": tactic, "difficulty": avg_weight})
    
    if not Silent:
        print(f"[+] Found {len(mitre_tactics)} unique MITRE tactics")
    
    # Create a challenge data structure to pass to create_C_matrix
    challenge_data = {
        "challenge_name": "Baseline",
        "category": "Analysis",
        "difficulty": 1,
        "mitre_tactics": mitre_tactics
    }
    
    return challenge_data

def compute_N_matrix(C, M):
    global Silent
    """Computes N (NICE mapping) from C and M using element-wise multiplication."""
    if Silent:
        return np.multiply(C, M)  # Element-wise multiplication
    else:
        result = np.multiply(C, M)  # Element-wise multiplication
        print(f"[+] Computed N matrix with shape {result.shape}")
        return result

# Example MITRE-to-NICE Mapping (M matrix with 5 NICE categories)
def load_matrix_from_csv(file_path):
    global Silent
    global MITRE_INDEX_MAPPING
    """
    Load the MITRE-to-NICE mapping matrix from a CSV file.
    
    The CSV file should contain rows representing MITRE techniques and
    columns representing NICE categories, with values representing the mapping weights.
    """
    try:
        # Load the CSV data using numpy's genfromtxt
        data = np.genfromtxt(file_path, delimiter=',', dtype=None, names=True, encoding='utf-8')
        # Extract the MITRE TTP IDs and their corresponding values
        mitre_ids = data['MITRE_TTP']
        values = data['Sum'].astype(float)
        
        # Create a dictionary mapping MITRE IDs to their indices
        # Convert all IDs to plain strings to avoid type comparison issues
        MITRE_INDEX_MAPPING = {str(mitre_id): i for i, mitre_id in enumerate(mitre_ids)}
        
        if not Silent:
            print("MITRE_INDEX_MAPPING created with keys:", list(MITRE_INDEX_MAPPING.keys())[:5], "... (and more)")
        
        # Create the M matrix (vector) from the values
        M = values
        if Silent:
            return M
        else:
            print(f"[+] Loaded {file_path} matrix with shape {M.shape}")
            return M
    except Exception as e:
        print(f"[-] ERROR: Failed to load matrix from {file_path}: {e}")
        # Return a default small matrix as fallback
        return 1

def cosine_similarity(v1, v2):
    global Silent
    """
    Computes the cosine similarity between two vectors.
    
    Args:
        v1: First vector (numpy array)
        v2: Second vector (numpy array)
        
    Returns:
        float: Cosine similarity score between -1 and 1
    """
    # Calculate dot product and magnitudes
    dot_product = np.dot(v1, v2)
    norm_v1 = np.linalg.norm(v1)
    norm_v2 = np.linalg.norm(v2)
    
    # Avoid division by zero, set similarity to the nearest calculated value to zero on the positive side
    if norm_v1 == 0 :
        norm_v1 = 0.020618556701030924
    
    if Silent:
        # Compute cosine similarity
        return dot_product / (norm_v1 * norm_v2)
    else:
        sim = dot_product / (norm_v1 * norm_v2)
        print(f"[+] Calculated cosine similarity: {sim}")
        return sim

def calculate_probability(similarity_score):
    global Silent
    # Get Alpha and Beta
    probability_elements = load_yaml("../baseline_files/alpha_beta_params.yaml")
    alpha = probability_elements.get("alpha", 1.0)
    beta = probability_elements.get("beta", 0.0)
    P = 1 / (1 + np.exp(-alpha * similarity_score + beta))
    if Silent:
        return P
    else:
        print(f"[+] Calculated real-world likeness probability: {P}")
        return P

def main():
    """
    Main function to load data and compute NICE impact vectors for CTF challenges.
    This function handles command-line argument parsing, loads necessary matrices and challenge data,
    computes impact vectors, and calculates the real-world likeness probability of a CTF challenge.
    Command-line arguments:
        challenge_file: Path to the YAML challenge file containing challenge metadata
        --baseline, -B: Calculate baseline metrics
        --similarity, -S: Calculate similarity metrics
    Returns:
        int: 0 for successful execution, 1 if an error occurred
    Raises:
        Various exceptions may be raised during file loading or calculation processes
    Example usage:
        python likeness_model.py challenge.yaml
        python likeness_model.py challenge.yaml --baseline
        python likeness_model.py challenge.yaml --similarity
    """
    global Silent

    """Main function to load data and compute NICE impact vectors."""
        # Set up argument parsing
    parser = argparse.ArgumentParser(
        description="Calculate real-world likeness probability of a CTF challenge.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Example usage:
        python likeness_model.py challenge.yaml
        python likeness_model.py challenge.yaml --baseline
        python likeness_model.py challenge.yaml --similarity"""
        )
    parser.add_argument('challenge_file', help="Path to the YAML challenge file")
    parser.add_argument('--baseline', '-B', action='store_true', default=False,help="Calculate baseline")
    parser.add_argument('--similarity', '-S', action='store_true', default=False, help="Calculate similarity")
    parser.add_argument('--output', '-O', default=False, help="Output file path")
    parser.add_argument('--silent', '-s', action='store_true', help="Run in silent mode")

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    args = parser.parse_args()

    if args.silent:
        Silent = True
    try:
        # Load YAML challenge data
        # Example data:
        # challenge_name: "OS Command Injection"
        # category: "Web Exploitation"
        # difficulty: 0.8
        # mitre_tactics:
        #   - technique_id: "T1202"  # Indirect Command Execution
        #     relevance_weight: 0.8
        #   - technique_id: "T1059.004"  # Unix Shell Execution
        #   - technique_id: "T1059.003"  # Windows Command Execution
        challenge_data = load_yaml(args.challenge_file)
        if not Silent:
            print(f"[+] Challenge: {challenge_data.get('challenge_name', 'Unknown')}")
            print(f"[+] Category: {challenge_data.get('category', 'Unknown')}")
            print(f"[+] Difficulty: {challenge_data.get('difficulty', 'Unknown')}")
        # Get the second column from the MITRE mapping
        M = load_matrix_from_csv("../baseline_files/MITRE-to-NICE-M-matrix.csv")
        # Create the C matrix using the challenge data
        
        
        
        if args.baseline:
            B = generate_baseline(args.challenge_file)
            write_yaml(B, "../baseline_files/baseline.yaml")
            #N = compute_N_matrix(B, M)
            return 0
        elif args.similarity:
            # Calculate the similarity
            C = create_C_matrix(challenge_data)
            B = load_yaml("../baseline_files/baseline.yaml")
            B = create_C_matrix(B)
            N = compute_N_matrix(C, M)
            similarity_score = cosine_similarity(N, B)
            return 0
        
        C = create_C_matrix(challenge_data)
        B = load_yaml("../baseline_files/baseline.yaml")
        B = create_C_matrix(B)
        N = compute_N_matrix(C, M)
        similarity_score = cosine_similarity(N, B)

                
        probability = calculate_probability(similarity_score, alpha, beta)
    except Exception as e:
        print(f"[-] ERROR: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())

