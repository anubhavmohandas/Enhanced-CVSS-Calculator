#!/usr/bin/env python3
"""
CVSS v3.1 Risk Calculator
A Python implementation of the Common Vulnerability Scoring System v3.1

Author: Based on student guide requirements
Version: 1.0
"""

import math
from typing import Dict, Tuple

class CVSSCalculator:
    """CVSS v3.1 Calculator implementing the complete scoring algorithm"""
    
    def __init__(self):
        # CVSS v3.1 Metric Values
        self.attack_vector = {
            'Network': 0.85,
            'Adjacent': 0.62,
            'Local': 0.55,
            'Physical': 0.20
        }
        
        self.attack_complexity = {
            'Low': 0.77,
            'High': 0.44
        }
        
        self.privileges_required = {
            'unchanged': {  # When Scope is Unchanged
                'None': 0.85,
                'Low': 0.62,
                'High': 0.27
            },
            'changed': {    # When Scope is Changed
                'None': 0.85,
                'Low': 0.68,
                'High': 0.50
            }
        }
        
        self.user_interaction = {
            'None': 0.85,
            'Required': 0.62
        }
        
        self.scope = {
            'Unchanged': 'unchanged',
            'Changed': 'changed'
        }
        
        self.impact_metrics = {
            'None': 0.00,
            'Low': 0.22,
            'High': 0.56
        }
        
        # Severity ratings
        self.severity_ratings = {
            (0.0, 0.0): "None",
            (0.1, 3.9): "Low",
            (4.0, 6.9): "Medium", 
            (7.0, 8.9): "High",
            (9.0, 10.0): "Critical"
        }
        
    def get_severity_rating(self, score: float) -> Tuple[str, str]:
        """Get severity rating and color for a CVSS score"""
        if score == 0.0:
            return "None", "⚪"
        elif 0.1 <= score <= 3.9:
            return "Low", "🟢"
        elif 4.0 <= score <= 6.9:
            return "Medium", "🟡"
        elif 7.0 <= score <= 8.9:
            return "High", "🟠"
        elif 9.0 <= score <= 10.0:
            return "Critical", "🔴"
        else:
            return "Unknown", "❓"
    
    def calculate_exploitability(self, av: str, ac: str, pr: str, ui: str, scope: str) -> float:
        """Calculate the Exploitability Score"""
        scope_key = self.scope[scope]
        pr_value = self.privileges_required[scope_key][pr]
        
        exploitability = (8.22 * 
                         self.attack_vector[av] * 
                         self.attack_complexity[ac] * 
                         pr_value * 
                         self.user_interaction[ui])
        
        return round(exploitability, 2)
    
    def calculate_impact(self, scope: str, c: str, i: str, a: str) -> float:
        """Calculate the Impact Score"""
        # Calculate Impact Sub Score (ISS)
        iss = 1 - ((1 - self.impact_metrics[c]) * 
                   (1 - self.impact_metrics[i]) * 
                   (1 - self.impact_metrics[a]))
        
        if scope == 'Unchanged':
            impact = 6.42 * iss
        else:  # Changed
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        
        return max(0, round(impact, 2))
    
    def calculate_base_score(self, exploitability: float, impact: float, scope: str) -> float:
        """Calculate the final Base Score"""
        if impact <= 0:
            return 0.0
        
        if scope == 'Unchanged':
            base_score = impact + exploitability
        else:  # Changed
            base_score = 1.08 * (impact + exploitability)
        
        # Apply ceiling (round up) and cap at 10.0
        base_score = min(10.0, math.ceil(base_score * 10) / 10)
        
        return base_score
    
    def calculate(self, metrics: Dict[str, str]) -> Dict[str, any]:
        """Main calculation method"""
        try:
            # Extract metrics
            av = metrics['Attack Vector']
            ac = metrics['Attack Complexity'] 
            pr = metrics['Privileges Required']
            ui = metrics['User Interaction']
            scope = metrics['Scope']
            c = metrics['Confidentiality']
            i = metrics['Integrity']
            a = metrics['Availability']
            
            # Calculate scores
            exploitability = self.calculate_exploitability(av, ac, pr, ui, scope)
            impact = self.calculate_impact(scope, c, i, a)
            base_score = self.calculate_base_score(exploitability, impact, scope)
            
            # Get severity rating
            severity, color = self.get_severity_rating(base_score)
            
            return {
                'exploitability_score': exploitability,
                'impact_score': impact,
                'base_score': base_score,
                'severity': severity,
                'severity_color': color,
                'vector_string': self.generate_vector_string(metrics)
            }
            
        except KeyError as e:
            raise ValueError(f"Missing or invalid metric: {e}")
        except Exception as e:
            raise ValueError(f"Calculation error: {e}")
    
    def generate_vector_string(self, metrics: Dict[str, str]) -> str:
        """Generate CVSS vector string"""
        abbrev = {
            'Attack Vector': {'Network': 'N', 'Adjacent': 'A', 'Local': 'L', 'Physical': 'P'},
            'Attack Complexity': {'Low': 'L', 'High': 'H'},
            'Privileges Required': {'None': 'N', 'Low': 'L', 'High': 'H'},
            'User Interaction': {'None': 'N', 'Required': 'R'},
            'Scope': {'Unchanged': 'U', 'Changed': 'C'},
            'Confidentiality': {'None': 'N', 'Low': 'L', 'High': 'H'},
            'Integrity': {'None': 'N', 'Low': 'L', 'High': 'H'},
            'Availability': {'None': 'N', 'Low': 'L', 'High': 'H'}
        }
        
        vector = "CVSS:3.1"
        metric_order = ['Attack Vector', 'Attack Complexity', 'Privileges Required', 
                       'User Interaction', 'Scope', 'Confidentiality', 'Integrity', 'Availability']
        
        for metric in metric_order:
            short_metric = metric.replace(' ', '')[0:2] if metric != 'Privileges Required' else 'PR'
            if metric == 'Attack Vector': short_metric = 'AV'
            elif metric == 'Attack Complexity': short_metric = 'AC'  
            elif metric == 'User Interaction': short_metric = 'UI'
            elif metric == 'Scope': short_metric = 'S'
            elif metric == 'Confidentiality': short_metric = 'C'
            elif metric == 'Integrity': short_metric = 'I'
            elif metric == 'Availability': short_metric = 'A'
            
            vector += f"/{short_metric}:{abbrev[metric][metrics[metric]]}"
        
        return vector

def print_header():
    """Print program header"""
    print("="*60)
    print("🛡️  CVSS v3.1 Risk Calculator")
    print("   Common Vulnerability Scoring System Calculator")
    print("="*60)
    print()

def print_metrics_guide():
    """Print quick reference guide"""
    print("\n📋 QUICK REFERENCE GUIDE:")
    print("-" * 30)
    
    print("🌐 Attack Vector:")
    print("   Network (N) - Internet attackable")
    print("   Adjacent (A) - Same network required") 
    print("   Local (L) - Local access required")
    print("   Physical (P) - Physical access required")
    
    print("\n🔧 Attack Complexity:")
    print("   Low (L) - Easy to exploit")
    print("   High (H) - Hard to exploit")
    
    print("\n🔑 Privileges Required:")
    print("   None (N) - No authentication needed")
    print("   Low (L) - Basic user privileges")
    print("   High (H) - Admin privileges required")
    
    print("\n👆 User Interaction:")
    print("   None (N) - No user interaction")
    print("   Required (R) - User must interact")
    
    print("\n📦 Scope:")
    print("   Unchanged (U) - Single component")
    print("   Changed (C) - Multiple components")
    
    print("\n💥 Impact Metrics (C/I/A):")
    print("   None (N) - No impact")
    print("   Low (L) - Limited impact") 
    print("   High (H) - Complete impact")
    print()

def get_user_input(metric: str, options: list) -> str:
    """Get user input for a specific metric"""
    while True:
        print(f"\n{metric}:")
        for i, option in enumerate(options, 1):
            print(f"  {i}. {option}")
        
        try:
            choice = input(f"Select {metric} (1-{len(options)}): ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return options[idx]
            else:
                print(f"❌ Please enter a number between 1 and {len(options)}")
        except ValueError:
            print("❌ Please enter a valid number")

def load_mysql_scenario() -> Dict[str, str]:
    """Load the MySQL example scenario from the guide"""
    return {
        'Attack Vector': 'Network',
        'Attack Complexity': 'Low', 
        'Privileges Required': 'Low',
        'User Interaction': 'None',
        'Scope': 'Unchanged',
        'Confidentiality': 'High',
        'Integrity': 'None',
        'Availability': 'None'
    }

def display_results(results: Dict[str, any], metrics: Dict[str, str]):
    """Display calculation results"""
    print("\n" + "="*60)
    print("📊 CVSS CALCULATION RESULTS")
    print("="*60)
    
    print(f"\n🎯 SCORES:")
    print(f"   Exploitability Score: {results['exploitability_score']:.1f}/10.0")
    print(f"   Impact Score:        {results['impact_score']:.1f}/10.0") 
    print(f"   Base Score:          {results['base_score']:.1f}/10.0")
    
    print(f"\n🚦 SEVERITY: {results['severity_color']} {results['severity']} ({results['base_score']:.1f})")
    
    print(f"\n🔗 Vector String:")
    print(f"   {results['vector_string']}")
    
    print(f"\n📋 INPUT SUMMARY:")
    for metric, value in metrics.items():
        print(f"   {metric}: {value}")
    
    # Risk interpretation
    severity = results['severity']
    print(f"\n💡 INTERPRETATION:")
    if severity == "Critical":
        print("   🚨 CRITICAL - Drop everything and fix immediately!")
    elif severity == "High": 
        print("   🔥 HIGH - Fix this very soon (within days)")
    elif severity == "Medium":
        print("   ⚠️  MEDIUM - Fix when convenient (within weeks)")
    elif severity == "Low":
        print("   📝 LOW - Fix eventually (next maintenance cycle)")
    else:
        print("   ✅ NONE - No security risk identified")
    
    print("="*60)

def main():
    """Main program loop"""
    calc = CVSSCalculator()
    
    print_header()
    
    while True:
        print("\n🎯 CVSS v3.1 Calculator Options:")
        print("1. Calculate new vulnerability score")
        print("2. Load MySQL scenario (from guide)")
        print("3. Show metrics guide")
        print("4. Exit")
        
        choice = input("\nSelect option (1-4): ").strip()
        
        if choice == '1':
            # Manual input
            print("\n📝 Enter vulnerability details:")
            
            metrics = {}
            metrics['Attack Vector'] = get_user_input("Attack Vector", 
                ['Network', 'Adjacent', 'Local', 'Physical'])
            metrics['Attack Complexity'] = get_user_input("Attack Complexity", 
                ['Low', 'High'])
            metrics['Privileges Required'] = get_user_input("Privileges Required", 
                ['None', 'Low', 'High'])
            metrics['User Interaction'] = get_user_input("User Interaction", 
                ['None', 'Required'])
            metrics['Scope'] = get_user_input("Scope", 
                ['Unchanged', 'Changed'])
            metrics['Confidentiality'] = get_user_input("Confidentiality Impact", 
                ['None', 'Low', 'High'])
            metrics['Integrity'] = get_user_input("Integrity Impact", 
                ['None', 'Low', 'High'])
            metrics['Availability'] = get_user_input("Availability Impact", 
                ['None', 'Low', 'High'])
            
            try:
                results = calc.calculate(metrics)
                display_results(results, metrics)
            except ValueError as e:
                print(f"❌ Error: {e}")
                
        elif choice == '2':
            # MySQL scenario
            print("\n🗄️  Loading MySQL Scenario...")
            print("A bug in MySQL that lets hackers read any data with basic login")
            
            metrics = load_mysql_scenario()
            results = calc.calculate(metrics)
            display_results(results, metrics)
            
        elif choice == '3':
            # Show guide
            print_metrics_guide()
            
        elif choice == '4':
            # Exit
            print("\n👋 Thank you for using CVSS Calculator!")
            print("🛡️  Remember: Stay secure, prioritize risks, and keep learning!")
            break
            
        else:
            print("❌ Invalid option. Please try again.")

if __name__ == "__main__":
    main()
