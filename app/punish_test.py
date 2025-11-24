import os
import subprocess
import re
import argparse

nice_file = "../baseline_files/NICE_Weighting.csv"
create_m_script = "create_M_matrix.py"
likeness_script = "likeness_model.py"
parse_challenges_script = "challenge_parser.py"
train_alpha_beta_script = "train_alfa_beta.py"
parse_github_script = "parse_challenge_probabilities.py"

def replace_in_file(filepath, old_string, new_string):
    """Replace occurrences of old_string with new_string in the specified file."""
    with open(filepath, 'r', encoding='utf-8') as file:
        content = file.read()
    content = content.replace(old_string, new_string)
    with open(filepath, 'w', encoding='utf-8') as file:
        file.write(content)

def empty_logfile(logfile):
    with open(logfile, 'w', encoding='utf-8') as log:
        log.write("punish_iteration,challenge_name,similarity_score,probability\n")

def gather_punishment_stats(logfile, i):
    with open("probability_weights.csv", 'r', encoding='utf-8') as prob_file:
        content = prob_file.read()
    with open(logfile, 'a', encoding='utf-8') as log:
        for line in content.splitlines():
            log.write("punish_iteration" + str(i) + "," + line + "\n")

def main():
    parser = argparse.ArgumentParser(description='Run punishment iteration tests')
    parser.add_argument('-i', '--iterations', type=int, default=97,
                        help='Number of punishment iterations (default: 97)')
    parser.add_argument('-l', '--logfile', type=str, default='punishment_log.csv',
                        help='Path to log file (default: punishment_log.csv)')
    parser.add_argument('-r', '--repo', type=str, default='/home/tgc/ntnu/iik3100_challenges/',
                        help='Path to challenges repository (default: /home/tgc/ntnu/iik3100_challenges/)')
    parser.add_argument('-b', '--baseline', type=str, default='../baseline_files/CWE-OWASP-to-MITRE.yml',
                        help='Path to baseline file (default: ../baseline_files/CWE-OWASP-to-MITRE.yml)')
    
    args = parser.parse_args()
    
    empty_logfile(args.logfile)
    for i in range(args.iterations):
        replace_in_file(nice_file, ",-"+str(i), ",-"+str(i+1))
        subprocess.run(["python3", create_m_script])
        subprocess.run(["python3", likeness_script, "--baseline", args.baseline])
        subprocess.run(["python3", parse_challenges_script])
        subprocess.run(["python3", train_alpha_beta_script])
        subprocess.run(["python3", parse_github_script, "-r", args.repo])
        gather_punishment_stats(args.logfile, i)

if __name__ == "__main__":
    main()


