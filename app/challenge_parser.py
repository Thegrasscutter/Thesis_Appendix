#!/usr/bin/env python3

import yaml
import numpy as np
from likeness_model import (
    load_yaml, write_yaml, create_C_matrix, compute_N_matrix, 
    cosine_similarity, load_matrix_from_csv, generate_baseline
)
import os

def calculate_challenge_similarities(challenges_file, output_file):
    """
    Calculate similarity scores for all challenges in the YAML file against a baseline.
    
    Args:
        challenges_file (str): Path to the YAML file containing challenge mappings
        output_file (str): Path to output the results
    """
    print(f"[+] Loading challenges from {challenges_file}")
    
    # Load the challenges data
    data = load_yaml(challenges_file)
    
    # Load the MITRE-to-NICE matrix
    M = load_matrix_from_csv("../baseline_files/MITRE-to-NICE-M-matrix.csv")
    
    # Generate or load baseline
    baseline_file = "../baseline_files/baseline.yaml"
    if not os.path.exists(baseline_file):
        print("[+] Generating baseline from CWE&OWASP mappings...")
        baseline_data = generate_baseline("../baseline_files/CWE-OWASP-to-MITRE.yml")
        write_yaml(baseline_data, baseline_file)
    else:
        print("[+] Loading existing baseline...")
        baseline_data = load_yaml(baseline_file)
    
    # Create baseline C matrix and N vector
    baseline_C = create_C_matrix(baseline_data)
    
    # Results dictionary to store all similarity calculations
    results = {
        "similarity_analysis": {
            "baseline_file": baseline_file,
            "matrix_file": "../baseline_files/MITRE-to-NICE-M-matrix.csv",
            "challenges": {}
        }
    }
    
    # Process each challenge in the challenge_mappings
    if 'challenge_mappings' in data:
        for challenge_id, challenge_info in data['challenge_mappings'].items():
            print(f"[+] Processing challenge: {challenge_id}")
            
            # Convert challenge info to the format expected by create_C_matrix
            challenge_data = {
                "challenge_name": challenge_id,
                "category": "CTF Challenge",
                "difficulty": challenge_info.get('difficulty', 0.5),
                "mitre_tactics": []
            }
            
            # Convert MITRE tactics to the expected format
            if 'mitre_tactics' in challenge_info:
                for tactic in challenge_info['mitre_tactics']:
                    challenge_data["mitre_tactics"].append({
                        "technique_id": str(tactic),
                        "difficulty": challenge_info.get('difficulty', 0.5)
                    })
            
            try:
                # Create C matrix for this challenge
                challenge_C = create_C_matrix(challenge_data)
                
                # Compute N vector for this challenge
                challenge_N = compute_N_matrix(challenge_C, M)
                
                # Calculate cosine similarity with baseline
                similarity_score = cosine_similarity(challenge_N, baseline_C)
                
                # Store results
                results["similarity_analysis"]["challenges"][challenge_id] = {
                    "difficulty": challenge_info.get('difficulty', 0.5),
                    "num_mitre_tactics": len(challenge_info.get('mitre_tactics', [])),
                    "mitre_tactics": challenge_info.get('mitre_tactics', []),
                    "similarity_score": float(similarity_score),
                    "c_matrix_nonzero": int(np.count_nonzero(challenge_C)),
                    "n_vector_sum": float(np.sum(challenge_N)),
                    "real_world_label": 0 if challenge_id.lower().startswith("mock") else 1
                }
                
                print(f"    Similarity score: {similarity_score:.4f}")
                
            except Exception as e:
                print(f"[-] ERROR processing {challenge_id}: {e}")
                results["similarity_analysis"]["challenges"][challenge_id] = {
                    "error": str(e),
                    "difficulty": challenge_info.get('difficulty', 0.5),
                    "num_mitre_tactics": len(challenge_info.get('mitre_tactics', [])),
                    "similarity_score": None,
                    "real_world_label": 0 if challenge_id.lower().startswith("mock") else 1
                }
    
    # Add summary statistics
    valid_scores = [
        result["similarity_score"] 
        for result in results["similarity_analysis"]["challenges"].values() 
        if result["similarity_score"] is not None
    ]
    
    if valid_scores:
        results["similarity_analysis"]["summary"] = {
            "total_challenges": len(results["similarity_analysis"]["challenges"]),
            "successful_calculations": len(valid_scores),
            "average_similarity": float(np.mean(valid_scores)),
            "min_similarity": float(np.min(valid_scores)),
            "max_similarity": float(np.max(valid_scores)),
            "std_similarity": float(np.std(valid_scores))
        }
    
    # Write results to output file
    write_yaml(results, output_file)
    print(f"[+] Results written to {output_file}")
    
    return results

def main():
    """Main function to run the similarity analysis."""
    challenges_file = "../baseline_files/HHC_NW_training.yaml"
    output_file = "../baseline_files/challenge_similarity_results.yaml"
    
    try:
        results = calculate_challenge_similarities(challenges_file, output_file)
        
        # Print summary
        summary = results["similarity_analysis"].get("summary", {})
        if summary:
            print("\n[+] Summary Statistics:")
            print(f"    Total challenges: {summary['total_challenges']}")
            print(f"    Successful calculations: {summary['successful_calculations']}")
            print(f"    Average similarity: {summary['average_similarity']:.4f}")
            print(f"    Min similarity: {summary['min_similarity']:.4f}")
            print(f"    Max similarity: {summary['max_similarity']:.4f}")
            print(f"    Standard deviation: {summary['std_similarity']:.4f}")
        
        return 0
        
    except Exception as e:
        print(f"[-] ERROR: {e}")
        return 1

if __name__ == "__main__":
    exit(main())