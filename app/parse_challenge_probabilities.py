#!/usr/bin/env python3
import yaml
import argparse
import os
import glob
import sys
from likeness_model import (
    load_yaml, write_yaml, create_C_matrix, compute_N_matrix, 
    cosine_similarity, load_matrix_from_csv, generate_baseline, calculate_probability
)

def parse_args():
    parser = argparse.ArgumentParser(description="Parse ctf yaml file and update weights in a CSV file.")
    parser.add_argument("-c", "--csv_file", help="Path to the CSV file to be updated. Default is 'probability_weights.csv'", default="probability_weights.csv")
    parser.add_argument("-cy", "--chall_yaml", help="Path to the YAML file containing ID-weight mappings.")
    parser.add_argument("-r", "--repo", help="Path to the repository containing challenges with \"chall.yaml\" files.")
    parser.add_argument("-s", "--silent", action="store_true", help="Run in silent mode without printing to console.")

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()

def calculate_challenge_similarities(challenges_file, silent=False):
    # Load the challenges data
    challenge_data = load_yaml(challenges_file)
    
    # Challenge Name
    challenge_name = challenges_file.split("/")[-2]

    # Load the MITRE-to-NICE matrix
    M = load_matrix_from_csv("../baseline_files/MITRE-to-NICE-M-matrix.csv")
    C = create_C_matrix(challenge_data)
    B = load_yaml("../baseline_files/baseline.yaml")
    B = create_C_matrix(B)
    N = compute_N_matrix(C, M)
    similarity_score = cosine_similarity(N, B)
      
    probability = calculate_probability(similarity_score)
    if not silent:
        print(f"[+] Challenge: {challenge_name}")
        print(f"    Similarity Score: {similarity_score}")
        print(f"    Probability: {probability}")
    return {
        "challenge_name": challenge_name,
        "similarity_score": similarity_score,
        "probability": probability
    }



def write_csv(data, output_file):
    with open(output_file, "w") as f:
        f.write("challenge_name,similarity_score,probability\n")
        for row in data:
            f.write(f"{row['challenge_name']},{row['similarity_score']},{row['probability']}\n")
    f.close()

def main():
    args = parse_args()
    data = []
    if args.repo:
        chall_yaml_files = glob.glob(os.path.join(args.repo, "**", "chall.yaml"), recursive=True)
        
        for chall_yaml in chall_yaml_files:
            if not args.silent:
                print(f"[+] Processing file: {chall_yaml}")
            result = calculate_challenge_similarities(chall_yaml, silent=args.silent)
            data.append(result)
        if not args.silent:
            print(f"[+] All challenges processed. Results saved to {args.csv_file}")
        write_csv(data, args.csv_file)
    elif args.chall_yaml:
        result = calculate_challenge_similarities(args.chall_yaml, silent=args.silent)
        data.append(result)
        write_csv(data, args.csv_file)



if __name__ == "__main__":
    main()