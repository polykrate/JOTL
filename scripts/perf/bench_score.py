import json
import os
import math
from pathlib import Path

# Scoring weights based on Parity's Dashboard Methodology
WEIGHTS = {
    'import_p50': 0.35,
    'import_p90': 0.25,
    'import_mean': 0.20,
    'import_p99': 0.10,
    'import_std_dev': 0.10
}

# Baseline team to normalize against (PolkaJam interpreted)
BASELINE_TEAM = "polkajam"

def calculate_test_score(stats):
    """Calculate the weighted score for a single test trace."""
    score = 0
    for key, weight in WEIGHTS.items():
        if key in stats and stats[key] > 0:
            score += stats[key] * weight
    return score

def load_all_reports(base_dir):
    """Load JSON reports and calculate scores per team per test."""
    reports = {}
    base_path = Path(base_dir)
    
    if not base_path.exists():
        return {}
        
    for team_dir in base_path.iterdir():
        if not team_dir.is_dir():
            continue
            
        team_name = team_dir.name
        reports[team_name] = {}
        
        for json_file in team_dir.glob("*.json"):
            test_name = json_file.stem
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    if 'stats' in data:
                        reports[team_name][test_name] = data['stats']
            except Exception as e:
                pass
                
    return reports

def calculate_final_scores(reports, target_tests=["safrole", "fallback", "storage", "storage_light"]):
    """Calculate the geometric mean of test scores for teams that have all target tests."""
    scores = {}
    
    for team, tests in reports.items():
        # Check if team has all required tests
        has_all = all(t in tests for t in target_tests)
        if not has_all:
            continue
            
        # Calculate score for each test
        test_scores = []
        p50s = []
        p90s = []
        
        for t in target_tests:
            stats = tests[t]
            t_score = calculate_test_score(stats)
            if t_score > 0:
                test_scores.append(t_score)
                p50s.append(stats.get('import_p50', 0))
                p90s.append(stats.get('import_p90', 0))
                
        if len(test_scores) == len(target_tests):
            # Geometric mean of test scores
            product = 1.0
            for s in test_scores:
                product *= s
            final_score = math.pow(product, 1.0 / len(test_scores))
            
            # Simple average for display P50/P90
            avg_p50 = sum(p50s) / len(p50s)
            avg_p90 = sum(p90s) / len(p90s)
            
            scores[team] = {
                'score': final_score,
                'p50': avg_p50,
                'p90': avg_p90
            }
            
    return scores

def print_leaderboard(scores, hardware_factor=1.0):
    """Print the formatted leaderboard."""
    if not scores:
        print("No complete data available.")
        return
        
    baseline_score = scores.get(BASELINE_TEAM, {}).get('score', 3.5)
    
    # Sort teams by score (lower is better)
    sorted_teams = sorted(scores.items(), key=lambda x: x[1]['score'])
    
    print("\n  Performance Rankings")
    print(f"  Baseline: PolkaJam (Score: {baseline_score:.1f})\n")
    print("  Rank  Team                Score    P50 (ms)   P90 (ms)   Relative Perf")
    print("  " + "-"*68)
    
    for i, (team, data) in enumerate(sorted_teams):
        score = data['score'] / hardware_factor
        p50 = data['p50'] / hardware_factor
        p90 = data['p90'] / hardware_factor
        
        relative = score / baseline_score
        
        # Color coding for relative performance
        if relative < 1.0:
            rel_str = f"\033[32m{1/relative:.1f}x faster\033[0m" # Green
        elif abs(relative - 1.0) < 0.05:
            rel_str = f"\033[35mbaseline\033[0m" # Purple
        elif relative < 2.0:
            rel_str = f"\033[33m{relative:.1f}x slower\033[0m" # Yellow
        else:
            rel_str = f"\033[31m{relative:.1f}x slower\033[0m" # Red
            
        print(f"  {i+1:<4}  {team:<18}  {score:>5.1f}    {p50:>8.2f}   {p90:>8.2f}   {rel_str:>20}")

if __name__ == "__main__":
    reports = load_all_reports("/home/polycrate/Projets/Jam/jam-conformance/fuzz-perf/0.7.2")
    scores = calculate_final_scores(reports)
    
    print("\n" + "="*80)
    print(" ACTUAL HARDWARE (Intel Core i7-10610U)")
    print("="*80)
    print_leaderboard(scores, hardware_factor=1.0)
    
    print("\n\n" + "="*80)
    print(" EXTRAPOLATED HARDWARE (AMD Threadripper 3970X Equivalent - ~2.2x factor)")
    print("="*80)
    print_leaderboard(scores, hardware_factor=2.2)
    print("\n")

