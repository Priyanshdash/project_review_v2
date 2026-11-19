"""Deep Reinforcement Learning (DRL) Response Orchestrator for CyberSentinel-LLM.
Implements the Markov Decision Process (MDP), PPO Policy Network, and Safe Sandbox Environment
defined in Section 4.6, Equations (22)-(25), and Algorithm 2 of the research paper.
"""

from __future__ import annotations
import os
import time
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

from .agents import RESPONSE_ACTIONS


class CyberIncidentEnv:
    """Gym-compatible Incident Response Simulation Environment (Section 4.6).
    Replays threat scenarios and models the effect of response actions on system state and services.
    """

    def __init__(self, scenarios: list[dict] | None = None, seed: int = 42):
        np.random.seed(seed)
        self.scenarios = scenarios or self._default_scenarios()
        self.idx = 0
        self.current_scenario = None
        self.state = None

    def _default_scenarios(self) -> list[dict]:
        """Provides simulated historical incident scenarios."""
        return [
            {"is_anomaly": 0, "threat_id": 0, "confidence": 0.98, "utilization": 0.25, "target_action": 0},
            {"is_anomaly": 1, "threat_id": 1, "confidence": 0.92, "utilization": 0.65, "target_action": 2},  # Malware -> Terminate
            {"is_anomaly": 1, "threat_id": 2, "confidence": 0.95, "utilization": 0.85, "target_action": 3},  # DDoS -> Firewall
            {"is_anomaly": 1, "threat_id": 3, "confidence": 0.89, "utilization": 0.40, "target_action": 4},  # Phishing -> Suspend
            {"is_anomaly": 1, "threat_id": 4, "confidence": 0.91, "utilization": 0.50, "target_action": 4},  # Insider -> Suspend
            {"is_anomaly": 1, "threat_id": 5, "confidence": 0.97, "utilization": 0.70, "target_action": 1},  # APT -> Isolate
            {"is_anomaly": 1, "threat_id": 6, "confidence": 0.65, "utilization": 0.55, "target_action": 6},  # Zero-day -> Escalate
        ] * 20

    def reset(self) -> np.ndarray:
        self.idx = 0
        np.random.shuffle(self.scenarios)
        self.current_scenario = self.scenarios[self.idx]
        self.state = self._get_obs()
        return self.state

    def _get_obs(self) -> np.ndarray:
        s = self.current_scenario
        # State vector s_t = [h_t^(LLM), s_D(t), \hat{y}_t, u_t] (Eq. 22)
        h_llm = float(s["confidence"])
        s_d = float(s["is_anomaly"])
        y_hat = float(s["threat_id"]) / 6.0
        u_t = float(s["utilization"])
        return np.array([h_llm, s_d, y_hat, u_t], dtype=np.float32)

    def step(self, action: int) -> tuple[np.ndarray, float, bool, dict]:
        """Executes action, computes Eq. (24) reward, and returns next state."""
        s = self.current_scenario
        target = s["target_action"]
        is_anom = s["is_anomaly"]

        # Reward components (Eq. 24): R = alpha1*R_detect + alpha2*R_response - alpha3*C_penalty
        r_detect = 0.0
        r_response = 0.0
        c_penalty = 0.0

        if is_anom:
            if action != 0:
                r_detect = 1.0  # True positive mitigation
                if action == target:
                    r_response = 0.8  # Optimal mitigation
                else:
                    r_response = 0.4  # Suboptimal mitigation
            else:
                r_detect = -0.5  # False negative (missed anomaly)
        else:
            if action == 0:
                r_detect = 1.0  # Correct nominal pass
                r_response = 0.2
            else:
                # False positive: disrupted benign service
                c_penalty = 0.3 + 0.1 * (1 if action in [1, 2, 4] else 0)

        # Alpha weights from paper Section 4.6
        reward = 1.0 * r_detect + 1.0 * r_response - 1.0 * c_penalty

        self.idx += 1
        done = self.idx >= len(self.scenarios)
        if not done:
            self.current_scenario = self.scenarios[self.idx]
            self.state = self._get_obs()
        else:
            self.state = np.zeros(4, dtype=np.float32)

        info = {
            "correct_action": action == target,
            "disruptive_fp": (is_anom == 0 and action != 0),
            "simulated_action_name": RESPONSE_ACTIONS[min(action, len(RESPONSE_ACTIONS) - 1)]
        }
        return self.state, float(reward), done, info


class PPOPolicyNetwork(nn.Module):
    r"""PPO Policy Network implementing Eq. (23):
    \pi_\theta(a|s_t) = softmax(W_\pi \cdot ReLU(W_s s_t + b_s) + b_\pi)
    """

    def __init__(self, state_dim: int = 4, action_dim: int = 7, hidden_dim: int = 64):
        super().__init__()
        self.actor = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, action_dim)
        )
        self.critic = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1)
        )

    def forward(self, state: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        logits = self.actor(state)
        value = self.critic(state)
        return logits, value

    def predict_action(self, state: list[float] | np.ndarray) -> int:
        self.eval()
        with torch.no_grad():
            s_tensor = torch.tensor(state, dtype=torch.float32).unsqueeze(0)
            logits, _ = self.forward(s_tensor)
            probs = torch.softmax(logits, dim=-1)
            action = int(torch.argmax(probs, dim=-1).item())
        return action


def train_ppo_orchestrator(episodes: int = 50, epochs_per_update: int = 3, lr: float = 0.001) -> tuple[PPOPolicyNetwork, list[float]]:
    """Trains the response orchestrator via PPO (Algorithm 2)."""
    env = CyberIncidentEnv()
    policy = PPOPolicyNetwork(state_dim=4, action_dim=7, hidden_dim=64)
    optimizer = optim.Adam(policy.parameters(), lr=lr)

    eps_clip = 0.2
    gamma = 0.99
    reward_history = []

    print(f"Training PPO Response Orchestrator ({episodes} episodes)...")
    for ep in range(episodes):
        state = env.reset()
        states, actions, log_probs, rewards, values, dones = [], [], [], [], [], []

        done = False
        total_ep_reward = 0.0

        while not done:
            s_t = torch.tensor(state, dtype=torch.float32).unsqueeze(0)
            logits, val = policy(s_t)
            probs = torch.softmax(logits, dim=-1)
            dist = torch.distributions.Categorical(probs)
            action = dist.sample()

            next_state, reward, done, _ = env.step(action.item())

            states.append(s_t)
            actions.append(action)
            log_probs.append(dist.log_prob(action))
            rewards.append(reward)
            values.append(val)
            dones.append(done)

            state = next_state
            total_ep_reward += reward

        reward_history.append(total_ep_reward)

        # Compute discounted returns
        returns = []
        discounted = 0.0
        for r in reversed(rewards):
            discounted = r + gamma * discounted
            returns.insert(0, discounted)
        returns = torch.tensor(returns, dtype=torch.float32)
        if len(returns) > 1 and returns.std() > 1e-5:
            returns = (returns - returns.mean()) / (returns.std() + 1e-7)

        # PPO Policy Update (Eq. 25)
        old_states = torch.cat(states)
        old_actions = torch.stack(actions)
        old_log_probs = torch.stack(log_probs).detach()

        for _ in range(epochs_per_update):
            curr_logits, curr_vals = policy(old_states)
            curr_probs = torch.softmax(curr_logits, dim=-1)
            curr_dist = torch.distributions.Categorical(curr_probs)
            curr_log_probs = curr_dist.log_prob(old_actions)

            ratios = torch.exp(curr_log_probs - old_log_probs)
            advantages = returns - curr_vals.squeeze(-1).detach()

            surr1 = ratios * advantages
            surr2 = torch.clamp(ratios, 1.0 - eps_clip, 1.0 + eps_clip) * advantages

            actor_loss = -torch.min(surr1, surr2).mean()
            critic_loss = nn.MSELoss()(curr_vals.squeeze(-1), returns)
            loss = actor_loss + 0.5 * critic_loss

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        if (ep + 1) % 10 == 0 or ep == episodes - 1:
            print(f"  Episode {ep+1}/{episodes} -> Total Reward: {total_ep_reward:.2f}")

    return policy, reward_history
