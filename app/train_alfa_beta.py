import numpy as np
import scipy.optimize as opt
from sklearn.linear_model import LogisticRegression
import likeness_model
import yaml

alpha_beta_file = '../baseline_files/challenge_similarity_results.yaml'
with open(alpha_beta_file, "r") as file:
    data = yaml.safe_load(file)
S = np.array([])
labels = np.array([])
for challenge_id, challenge_data in data['similarity_analysis']['challenges'].items():
    S = np.append(S, challenge_data.get('similarity_score', 0.2072))
    labels = np.append(labels, challenge_data.get('real_world_label', 1))  # Assuming binary labels for relevance

# Logistic Regression to fit α and β
def sigmoid(S, alpha, beta):
    return 1 / (1 + np.exp(-alpha * S + beta))

def loss(params, S, labels):
    alpha, beta = params
    predictions = sigmoid(S, alpha, beta)
    return -np.sum(labels * np.log(predictions) + (1 - labels) * np.log(1 - predictions))  # Log-likelihood loss

# Initial guess for α and β
initial_params = [1, 0]

# Optimize α and β
opt_params = opt.minimize(loss, initial_params, args=(S, labels), method='BFGS').x
alpha_trained, beta_trained = opt_params
# Save alpha and beta to a file
with open('../baseline_files/alpha_beta_params.yaml', 'w') as f:
    yaml.dump({"alpha": float(alpha_trained), "beta": float(beta_trained)}, f)

print(f"Optimized α: {alpha_trained}")
print(f"Optimized β: {beta_trained}")
